import socket
from datetime import datetime

target = input("Enter target IP: ")

ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

report = []

print("\nVULNERABILITY SCANNER")
print("-" * 40)

for port, service in ports.items():

    sock = socket.socket()
    sock.settimeout(0.3)

    if sock.connect_ex((target, port)) == 0:
        result = f"Port {port} OPEN - {service}"
        print(result)
        report.append(result)

        if port == 21:
            report.append("Risk: FTP may use unencrypted communication")

        if port == 23:
            report.append("Risk: Telnet uses insecure communication")

    sock.close()

with open("vulnerability_report.txt", "w") as file:
    file.write("VULNERABILITY SCANNER REPORT\n")
    file.write("=" * 40 + "\n")
    file.write("Target: " + target + "\n")
    file.write("Date: " + str(datetime.now()) + "\n\n")

    for item in report:
        file.write(item + "\n")

print("\nScan completed!")
print("Report saved as vulnerability_report.txt")