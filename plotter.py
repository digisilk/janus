from datetime import datetime
import csv
import requests
from collections import defaultdict
from androguard.misc import AnalyzeAPK
import pandas as pd
from androguard.core.bytecodes import apk, dvm
import tldextract
import re
import multiprocessing as mp
import plotly.graph_objects as go
import urllib.request
import gzip
import plotly.io as pio
import zipfile
import subprocess
from flask import session
import os
import uuid


filename = "latest_with-added-date.csv"

# Update every so often
# Check if the file exists
if not os.path.isfile(filename):
    url = "https://androzoo.uni.lu/static/lists/latest_with-added-date.csv.gz"
    urllib.request.urlretrieve(url, filename + ".gz")
    print("File downloaded.")

    # Check if the downloaded file is a gzip file
    if filename.endswith(".gz"):
        # Extract the gzip file
        with gzip.open(filename + ".gz", "rb") as f_in:
            with open(filename, "wb") as f_out:
                f_out.write(f_in.read())
        print("File extracted.")

def find_sha256_vercode_vtscandate(package_name, csv_path, start_date, end_date):
    print("Searching for SHA256, version code, and VT scan date in the CSV file...")
    sha256_vercode_vtscandate_values = []
    start_date = datetime.strptime(start_date, '%Y-%m-%d %H:%M:%S.%f')
    end_date = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S.%f')

    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if row[5] == package_name:
                vt_scan_date = datetime.strptime(row[10], '%Y-%m-%d %H:%M:%S.%f')
                if start_date <= vt_scan_date <= end_date:
                    sha256_vercode_vtscandate_values.append((row[0], row[6], row[10]))

    # Sort by vt_scan_date in ascending order
    sha256_vercode_vtscandate_values.sort(key=lambda x: datetime.strptime(x[2], '%Y-%m-%d %H:%M:%S.%f'))
    return sha256_vercode_vtscandate_values


def calculate_sampling_frequency(total_versions, desired_versions):
    print("Calculating sampling frequency...")
    print(max(1,total_versions // desired_versions))
    return max(1, total_versions // desired_versions)


def download_apk(sha256, vercode, vtscandate, package_name, apikey, folder):
    print(f"Downloading APK with SHA256: {sha256}...")
    os.makedirs(folder, exist_ok=True)
    url = f"https://androzoo.uni.lu/api/download?apikey={apikey}&sha256={sha256}"
    response = requests.get(url, stream=True)

    if response.status_code != 200:
        print(f"Failed to download APK with SHA256: {sha256}. HTTP status code: {response.status_code}")
        return

    filename = os.path.join(folder, f"{package_name}_{vercode}_{vtscandate}.apk")
    with open(filename, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)


def download_apks(package_names, apikey, folder, csv_path, start_date, end_date, desired_versions):
    print("Starting to download APKs...")
    for package_name in package_names:
        sha256_vercode_vtscandate_list = find_sha256_vercode_vtscandate(package_name, csv_path, start_date, end_date)
        sampling_frequency = calculate_sampling_frequency(len(sha256_vercode_vtscandate_list), desired_versions)
        sha256_vercode_vtscandate_list = sha256_vercode_vtscandate_list[::sampling_frequency]
        for sha256, vercode, vtscandate in sha256_vercode_vtscandate_list:
            download_apk(sha256, vercode, vtscandate, package_name, apikey, folder)



def analyze_folder(folder_path):
    print("Analyzing folder for APK files...")
    pool = mp.Pool(mp.cpu_count())

    # Generate file paths
    file_names = os.listdir(folder_path)

    # Process the files
    results = pool.starmap(process_file, [(file_name, folder_path) for file_name in file_names])

    # Update the version_subdomains and version_vtscandates dicts
    version_vtscandate_subdomains_counts = []
    for result in results:
        if result is not None:
            version_vtscandate_subdomains_counts.extend(result)

    return version_vtscandate_subdomains_counts

def extract_elements(file_path):
    print(f"Extracting domains and subdomains from file: {file_path}...")
    try:
        a = apk.APK(file_path)
        domains = []
        subdomains = []
        urls = []
        for dex in a.get_all_dex():
            dv = dvm.DalvikVMFormat(dex)
            for string in dv.get_strings():
                urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)

                for url in urls:
                    parsed_url = tldextract.extract(url)
                    domain = '.'.join(reversed([part for part in [parsed_url.domain, parsed_url.suffix] if part]))
                    subdomain = '.'.join(reversed([part for part in parsed_url if part]))

                    domains.append(domain)
                    subdomains.append(subdomain)

                    domains = [domain for domain in domains if valid_entry(domain)]
                    subdomains = [subdomain for subdomain in subdomains if valid_entry(subdomain)]

        return domains, subdomains
    except Exception as e:
        print(f'Error while extracting domains and subdomains from {file_path}: {str(e)}')
        return [], []


def extract_elements_with_manifest(file_path):
    print(f"Extracting domains and subdomains from file: {file_path}...")
    try:
        a = apk.APK(file_path)
        domains = []
        subdomains = []
        urls = []

        # Extract from AndroidManifest.xml
        manifest_xml = a.get_android_manifest_xml()
        for elem in manifest_xml.iter():
            for text in [elem.text] + list(elem.attrib.values()):
                if text is not None:
                    urls_in_text = re.findall(
                        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
                    urls.extend(urls_in_text)
                    print(urls_in_text)
        print(urls)

        # Extract from DEX files
        for dex in a.get_all_dex():
            dv = dvm.DalvikVMFormat(dex)
            for string in dv.get_strings():
                urls_in_string = re.findall(
                    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
                urls.extend(urls_in_string)

        # Parse the URLs to get domains and subdomains
        for url in urls:
            parsed_url = tldextract.extract(url)
            domain = '.'.join(reversed([part for part in [parsed_url.domain, parsed_url.suffix] if part]))
            subdomain = '.'.join(reversed([part for part in parsed_url if part]))

            if "%s" not in domain and valid_entry(domain):
                domains.append(domain)
            if "%s" not in subdomain and valid_entry(subdomain):
                subdomains.append(subdomain)

        return domains, subdomains
    except Exception as e:
        print(f'Error while extracting domains and subdomains from {file_path}: {str(e)}')
        return [], []

def valid_entry(entry):
    invalid_chars = ['$', '[', ']', '#', '%s']
    # Check if entry contains any invalid characters
    if any(char in entry for char in invalid_chars):
        return False
    # Check if entry doesn't contain a dot
    if '.' not in entry:
        return False
    # Check if entry is an IP address (all numbers and dots)
    if all(c.isdigit() or c == '.' for c in entry):
        return False
    return True

def check_string_for_urls(string, urls):
    if string is not None:
        new_urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
        urls.extend(new_urls)

def extract_elements_strings_util(file_path):
    print(f"Extracting domains and subdomains from file: {file_path}...")
    try:
        # Use the strings command to extract readable strings from the APK file.
        result = subprocess.run(['strings', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f'strings command failed: {result.stderr}')

        # Split the output into separate strings.
        strings = result.stdout.split('\n')

        domains = set()
        subdomains = set()
        for string in strings:
            urls = re.findall(
                r'(?:http[s]?://)?(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)

            for url in urls:
                parsed_url = tldextract.extract(url)
                domain = '.'.join(part for part in [parsed_url.domain, parsed_url.suffix] if part)
                subdomain = '.'.join(part for part in parsed_url if part)
                domains.add(domain)
                subdomains.add(subdomain)
        return list(domains), list(subdomains)
    except Exception as e:
        print(f'Error while extracting domains and subdomains from {file_path}: {str(e)}')
        return [], []


def check_string_for_urls(string, urls):
    if string is not None:
        found_urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\{\}]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
        urls.extend(found_urls)

def analyze_elements(folder_path):
    print(f"Analyzing folder for APK files and extracting domains and subdomains...")
    pool = mp.Pool(mp.cpu_count())

    # Generate file paths
    file_names = os.listdir(folder_path)

    # Process the files
    # results = pool.map(process_file, [(file_name, folder_path) for file_name in file_names])
    results = pool.starmap(process_file, [(file_name, folder_path) for file_name in file_names])

    version_vtscandate_domains_counts = []
    version_vtscandate_subdomains_counts = []

    for result in results:
        if result is not None:
            version = result["version"]
            vt_scan_date = result["vt_scan_date"]
            for domain, count in result["domains"]:
                version_vtscandate_domains_counts.append((version, vt_scan_date, domain, count))
            for subdomain, count in result["subdomains"]:
                version_vtscandate_subdomains_counts.append((version, vt_scan_date, subdomain, count))

    return version_vtscandate_domains_counts, version_vtscandate_subdomains_counts




def process_file(file_name, folder_path):
    if file_name.endswith('.apk'):
        print(f"Processing file: {file_name}...")
        file_path = os.path.join(folder_path, file_name)
        a, _, _ = AnalyzeAPK(file_path)
        version = a.get_androidversion_code()
        vt_scan_date = file_name.split('_')[2].split('.')[0]  # Extract vt_scan_date from the file name
        domains, subdomains = extract_elements(file_path)
        domain_counts = defaultdict(int)
        subdomain_counts = defaultdict(int)
        for domain in domains:
            domain_counts[domain] += 1
        for subdomain in subdomains:
            subdomain_counts[subdomain] += 1
        return {
            "version": version,
            "vt_scan_date": vt_scan_date,
            "domains": [(domain, count) for domain, count in domain_counts.items()],
            "subdomains": [(subdomain, count) for subdomain, count in subdomain_counts.items()]
        }
    else:
        return None


def count_apps(package_name, csv_path, start_date, end_date):
    print("Counting apps in the CSV file between given dates...")
    count = 0
    start_date = datetime.strptime(start_date, '%Y-%m-%d %H:%M:%S.%f')
    end_date = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S.%f')

    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if row[5] == package_name:
                vt_scan_date = datetime.strptime(row[10], '%Y-%m-%d %H:%M:%S.%f')
                if start_date <= vt_scan_date <= end_date:
                    count += 1

    return count


def plot_data(version_vtscandate_elements_counts, element_type, binary=False):
    print("Preparing data for plotting...")
    data = [{'Version': str(version), 'vt_scan_date': vt_scan_date, element_type.capitalize(): element, 'Count': count} for
            version, vt_scan_date, element, count in version_vtscandate_elements_counts]
    df = pd.DataFrame(data)
    if df.empty:
        print("No data to plot.")
        return

    print("Plotting data...")
    df['Version'] = df['Version'].astype(str)
    df_count_pivot = df.pivot_table(index=element_type.capitalize(), columns='Version', values='Count', aggfunc='sum', fill_value=0)
    df_date_pivot = df.pivot_table(index=element_type.capitalize(), columns='Version', values='vt_scan_date',
                                   aggfunc='first')  # Or use another aggregation function if multiple vt_scan_date for the same element-version

    # Sort the columns (which are the versions) numerically but keep them as strings
    df_count_pivot = df_count_pivot[sorted(df_count_pivot.columns, key=int)]

    df_date_pivot = df_date_pivot[sorted(df_date_pivot.columns, key=int)]

    legend = True

    if binary:
        colorscale = [[0, 'white'], [0.01, 'grey'], [1, 'grey']]  # two colors, for presence and absence
        zmax = 1
        title = f'{element_type.capitalize()} Presence Across Versions'
        legend = False
    else:
        colorscale = [[0, 'white'], [0.01, 'grey'], [0.2, 'grey'], [1, 'black']]
        zmax = df_count_pivot.values.max()
        title = f'{element_type.capitalize()} Frequency Across Versions'

    df_labels = df_count_pivot.copy()
    df_labels.index = df_labels.index.map(lambda x: '.'.join(reversed(x.split('.'))))

    fig = go.Figure(data=go.Heatmap(
        z=df_count_pivot.values,
        x=df_count_pivot.columns.tolist(),
        y=df_labels.index.tolist(),  # Use the reversed labels here
        text=df_date_pivot.values,
        hoverinfo='z+x+y+text',
        colorscale=colorscale,
        zmin=0,
        zmax=zmax,
        xgap=1,
        ygap=1,
        showscale=legend))

    version_labels = []
    for version in df_count_pivot.columns:
        version_data = df[df['Version'] == version]
        version_data_non_zero = version_data[version_data['Count'] > 0]
        if not version_data_non_zero.empty:
            date = version_data_non_zero['vt_scan_date'].iloc[0]
            date = datetime.strptime(date.split()[0], '%Y-%m-%d').strftime('%Y-%m-%d')
        else:
            date = 'N/A'
        version_labels.append(f"{version}<br>{date}")

    fig.update_layout(
        title=title,
        xaxis=dict(tickmode = 'array',
                   tickvals = df_count_pivot.columns,
                   ticktext = version_labels),
        yaxis=dict(autorange="reversed"),
    )

    # Convert plot to HTML
    plot_html = pio.to_html(fig, full_html=False)

    return plot_html


def plot_data_grouped_bar(version_vtscandate_elements_counts, element_type):
    print("Preparing data for plotting...")
    data = [{'Version': str(version), 'vt_scan_date': vt_scan_date, element_type.capitalize(): element, 'Count': count}
            for
            version, vt_scan_date, element, count in version_vtscandate_elements_counts]
    df = pd.DataFrame(data)
    if df.empty:
        print("No data to plot.")
        return

    print("Plotting data...")
    df['Version'] = df['Version'].astype(str)
    df_count_pivot = df.pivot_table(index=element_type.capitalize(), columns='Version', values='Count', aggfunc='sum',
                                    fill_value=0)
    df_date_pivot = df.pivot_table(index=element_type.capitalize(), columns='Version', values='vt_scan_date',
                                   aggfunc='first')  # Or use another aggregation function if multiple vt_scan_date for the same element-version

    # Sort the columns (which are the versions) numerically but keep them as strings
    df_count_pivot = df_count_pivot[sorted(df_count_pivot.columns, key=int)]
    df_date_pivot = df_date_pivot[sorted(df_date_pivot.columns, key=int)]

    df_count_pivot.index = df_count_pivot.index.map(lambda x: '.'.join(reversed(x.split('.'))))

    # Create a bar for each version
    bars = []
    for version in df_count_pivot.columns:
        counts = df_count_pivot[version].values.tolist()
        bars.append(go.Bar(name=version, x=df_count_pivot.index.tolist(), y=counts))


    title = f'{element_type.capitalize()} Count Across Versions'

    # Change the bar mode
    fig = go.Figure(data=bars)
    fig.update_layout(barmode='group', title=title, xaxis_title=element_type, yaxis_title="Count")

    # Convert plot to HTML
    plot_html = pio.to_html(fig, full_html=False)

    return plot_html


def run(apikey, packages, start_date, end_date):
    desired_versions = 10
    start_date += " 00:00:00.000000"
    end_date += " 00:00:00.000000"

    # Generate a unique session ID
    session_id = str(uuid.uuid4())
    session['id'] = session_id

    csv_path = "latest_with-added-date.csv"
    folder_path = f"folder_{session_id}"

    # Use the session ID in the file names
    file_subdomains_heatmap = f"plot_subdomains_heatmap_{session_id}.html"
    file_subdomains_binary = f"plot_subdomains_binary_{session_id}.html"
    file_domains_heatmap = f"plot_domains_heatmap_{session_id}.html"
    file_domains_binary = f"plot_domains_binary_{session_id}.html"
    file_domains_gb = f"plot_domains_grouped_bar_{session_id}.html"
    file_subdomains_gb = f"plot_subdomains_grouped_bar_{session_id}.html"


    # Download APKs
    download_apks(packages, apikey, folder_path, csv_path, start_date, end_date, desired_versions)

    # Analyze data
    version_vtscandate_domains, version_vtscandate_subdomains = analyze_elements(folder_path)

    # Plot data for subdomains
    plot_html_subdomains_heatmap = plot_data(version_vtscandate_subdomains, 'subdomain')
    plot_html_subdomains_binary = plot_data(version_vtscandate_subdomains, 'subdomain', binary=True)

    # Plot data for domains
    plot_html_domains_heatmap = plot_data(version_vtscandate_domains, 'domain')
    plot_html_domains_binary = plot_data(version_vtscandate_domains, 'domain', binary=True)

    plot_html_domains_gb = plot_data_grouped_bar(version_vtscandate_domains, 'domain')
    plot_html_subdomains_gb = plot_data_grouped_bar(version_vtscandate_subdomains, 'subdomain')

    # Write HTML content to files
    with open(file_subdomains_heatmap, "w") as file:
        file.write(plot_html_subdomains_heatmap)
    with open(file_subdomains_binary, "w") as file:
        file.write(plot_html_subdomains_binary)
    with open(file_domains_heatmap, "w") as file:
        file.write(plot_html_domains_heatmap)
    with open(file_domains_binary, "w") as file:
        file.write(plot_html_domains_binary)
    with open(file_domains_gb, "w") as file:
        file.write(plot_html_domains_gb)
    with open(file_subdomains_gb, "w") as file:
        file.write(plot_html_subdomains_gb)

    # Define zip file path
    zip_file_path = f"plots_{session_id}.zip"

    # Create a zip file
    with zipfile.ZipFile(zip_file_path, 'w') as zipf:
        zipf.write(file_subdomains_heatmap)
        zipf.write(file_subdomains_binary)
        zipf.write(file_domains_heatmap)
        zipf.write(file_domains_binary)
        zipf.write(file_domains_gb)
        zipf.write(file_subdomains_gb)

    # Return the zip file path
    return zip_file_path


