import re
from rich.console import Console
from rich.table import Table

def parse_line(line):
     #extract ip address
    ip_match=re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' , line)
    if not ip_match:
        return None
    ip = ip_match.group(0)

    #failed login
    if "Failed password" in line or "Failed none" in line:
        user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', line)
        username = user_match.group(1) if user_match else None
        event_type = "failed_password"if "Failed password" in line else "failed_none"
        return {"type": event_type, "ip": ip, "username": username}

        #succelssful login
    if "Accepted password" in line:
        user_match = re.search(r'for (\S+)', line)
        username = user_match.group(1) if user_match else None
        return {"type": "accepted_password", "ip": ip, "username": username}

    # invalid user
    if "Invalid user" in line:
        user_match = re.search(r'Invalid user\s+(\S+)', line)
        username = user_match.group(1) if user_match else None
        return {
            "type": "invalid_user","ip": ip,"username": username}

        #break in
    if "POSSIBLE BREAK-IN ATTEMPT" in line :
        return{"type":"possible_break_in", "ip":ip, "username":None}
    return None




def get_hour(line):
    try:
        time_part=line.split()[2]
        hour_str=time_part.split(":")[0]
        return int(hour_str)
    except(IndexError, ValueError):
        return None




def repeated_message(line):
    if "message repeated" not in line:
        return None
    match = re.search(r'message repeated (\d+) times: \[\s*(.*?)\s*\]', line)
    if match:
        count = int(match.group(1))
        inner_line = match.group(2)
        return count, inner_line
    return None




def update_ip_data(data,event,hour,count=1):
    if event is None:
        return
    ip = event["ip"]
    event_type=event["type"]
    username=event["username"]
    if ip not in data:
        data[ip]={
                "failed_password": 0,
                "failed_none": 0,
                "accepted_password": 0,
                "invalid_users": set(),
                "targeted_users": set(),
                "root_targeted": False,
                "possible_break_in": False,
                "hourly_data": {}
            }
    ip_data=data[ip]

    #store targeted users
    if username:
        ip_data["targeted_users"].add(username)
        if username == "root":
            ip_data["root_targeted"] = True

        #store event
    if event_type == "failed_password":
        ip_data["failed_password"] += count

    elif event_type == "failed_none":
        ip_data["failed_none"] += count

    elif event_type == "accepted_password":
        ip_data["accepted_password"] += count

    elif event_type == "invalid_user":
        ip_data["invalid_users"].add(username)

    elif event_type == "possible_break_in":
        ip_data["possible_break_in"] = True

    # store hourly failed attempts
    if event_type == "failed_password" or event_type == "failed_none":
        if hour not in ip_data["hourly_data"]:
            ip_data["hourly_data"][hour] = {"failed_password":0,"failed_none":0}
        ip_data["hourly_data"][hour][event_type] += count




def calculate_risk(ip_data):
    failed_total=ip_data["failed_password"]+ip_data["failed_none"]
    general_score = 0
    hourly_score = 0
    reasons = []

    #general failed attempts
    if failed_total >= 51:
        general_score += 4
        reasons.append("more than 50 failed attempts")
    elif failed_total >= 21:
        general_score += 3
        reasons.append("more than 20 failed attempts")
    elif failed_total >= 6:
        general_score += 2
        reasons.append("more than 5 failed attempts")
    elif failed_total >= 1:
        general_score += 1
        reasons.append("failed login attempts")

    #targeted users
    if len(ip_data["targeted_users"]) >= 4:
        general_score += 1
        reasons.append("multiple targeted users")

    #root
    if ip_data["root_targeted"]:
        general_score += 1
        reasons.append("root account targeted")

    #invalid users
    if len(ip_data["invalid_users"]) >= 3:
        general_score += 1
        reasons.append("multiple invalid users")

    #possible break in
    if ip_data["possible_break_in"]:
        general_score += 2
        reasons.append("possible break-in attempt")

    #hourly risk
    highest_hourly_failed=0
    for hour in ip_data["hourly_data"]:
        hourly_failed = (ip_data["hourly_data"][hour]["failed_password"]+ ip_data["hourly_data"][hour]["failed_none"])
        if hourly_failed > highest_hourly_failed:
                highest_hourly_failed = hourly_failed
    if highest_hourly_failed > 25:
        hourly_score = 3
        reasons.append("more than 25 failed attempts in one hour")
    elif highest_hourly_failed >= 11:
        hourly_score = 2
        reasons.append("11 to 25 failed attempts in one hour")
    elif highest_hourly_failed >= 6:
        hourly_score = 1
        reasons.append("6 to 10 failed attempts in one hour")

    final_score = general_score + hourly_score

    if final_score >= 7:
        risk_level = "HIGH"
    elif final_score >= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    return {
        "score": final_score,
        "level": risk_level,
        "reasons": reasons
    }




def generate_report(data):
    console=Console()
    table=Table(title="OpenSSH Security report")
    table.add_column("IP")
    table.add_column("Failed")
    table.add_column("Accepted")
    table.add_column("Users")
    table.add_column("Root")
    table.add_column("Invalid")
    table.add_column("Break-In")
    table.add_column("Risk")
    table.add_column("Level")

    for ip in data:
        ip_data=data[ip]
        risk =calculate_risk(ip_data)
        failed_total=ip_data["failed_password"]+ip_data["failed_none"]

        table.add_row(
                ip,
                str(failed_total),
                str(ip_data["accepted_password"]),
                str(len(ip_data["targeted_users"])),"Yes" if ip_data["root_targeted"] else "No",
                str(len(ip_data["invalid_users"])),"Yes" if ip_data["possible_break_in"] else "No",
                str(risk["score"]),
                risk["level"]
            )
    console.print(table)
    print("\nRisk reasons:\n")
    for ip in data:
         risk = calculate_risk(data[ip])
         if risk["reasons"]:
            print(ip + ":")
            for reason in risk["reasons"]:
                print("-", reason)



def main():
    data ={}
    file_name="OpenSSH_2k.log"
    with open(file_name,"r")as file:
        for line in file:
            hour=get_hour(line)
            repeated=repeated_message(line)
            if repeated:
                count,inner_line=repeated
                event=parse_line(inner_line)
                update_ip_data(data,event,hour,count)
            else:
                event =parse_line(line)
                update_ip_data(data,event,hour)
    generate_report(data)


if __name__ == "__main__":
    main()
