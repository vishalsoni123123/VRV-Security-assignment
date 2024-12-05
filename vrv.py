import csv
from collections import defaultdict

##################################          Function to parse the log file and extract the required information            ################################
def parse_log_file(log_file):
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split(' ')
            ip_address = parts[0]
            status_code = parts[8]
            endpoint = parts[6]

            # Count requests per IP
            ip_count[ip_address] += 1

            # Count accesses to endpoints
            endpoint_count[endpoint] += 1

            # Detect failed login attempts
            if status_code == '401' or 'Invalid credentials' in line:
                failed_logins[ip_address] += 1

    return ip_count, endpoint_count, failed_logins







############################            Function to display and save results            ###############################



def display_and_save_results(ip_count, endpoint_count, failed_logins, failed_login_threshold=10):
    # Sort IPs by request count in descending order
    sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

    # Find the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])

    # Detect suspicious activity based on failed login threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}

    # Print to terminal
    print("Requests per IP:")
    for ip, count in sorted_ip_count:
        print(f"{ip}\t{count}")

    print(f"\nMost Frequently Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_ips.items():
            print(f"{ip}\t{count}")

    # Save to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted_ip_count:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])








#############################         Main function to execute the script          #########################################################
def main():
    log_file = 'sample.log'
    ip_count, endpoint_count, failed_logins = parse_log_file(log_file)
    display_and_save_results(ip_count, endpoint_count, failed_logins)

if __name__ == "__main__":
    main()
