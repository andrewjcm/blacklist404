import subprocess, re, sys, shlex


def get_ip(log_line):
    ipv4_pattern = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    ip_match = re.search(ipv4_pattern, log_line)
    if not ip_match:
        return None
    return ip_match.group(0)


def is_404(log_line):
    match404 = re.search(" 404 ", log_line)
    if not match404:
        return False
    return True


def is_wp_login(log_line):
    match_wp_login = re.search(r"\/wp\-login", log_line)
    return True if match_wp_login else False


def should_block(log_line):
    if is_404(log_line) and is_wp_login(log_line):
        return True
    return False


def get_block_list(file_name):
    block_list = set()
    with open(file_name, "r") as access_log:
        for line in access_log:
            ip = get_ip(line)
            if should_block(line) and ip not in block_list:
                block_list.add(ip)
    return block_list

def get_all_previously_blocked():
    previously_blocked_ips = set()
    try:
        with open("block_list.txt", "r") as file:
            for line in file:
                previously_blocked_ips.add(line.strip("\n"))
        return previously_blocked_ips
    except FileNotFoundError:
        return previously_blocked_ips


def block_list_text(ip):
    with open("block_list.txt", "a") as file:
        file.write(ip + "\n")


def block_all(block_list):
    block_list -= get_all_previously_blocked()
    if len(block_list) > 0:
        for ip in block_list:
            print(f"Blocking ip: {ip}")
            block_list_text(ip)
            args = shlex.split(f"ufw deny from {ip} to any")
            subprocess.run(args)
    else:
        print("Nothing new to block.")


def main():
    args = sys.argv
    if not args[1]:
        raise Exception("Error: no filename given")
    file_name = args[1]
    block_list = get_block_list(file_name)
    if block_list:
        block_all(block_list)


if __name__ == "__main__":
    main()
