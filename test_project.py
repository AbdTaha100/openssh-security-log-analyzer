from project import parse_line, get_hour, repeated_message, calculate_risk
def test_parse_line():
    line1 = "Dec 10 07:07:38 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
    res1 = parse_line(line1)
    assert res1["type"] == "failed_password"
    assert res1["ip"] == "192.168.1.100"
    assert res1["username"] == "admin"
    line2 = "Dec 10 07:08:00 server sshd[1235]: Accepted password for root from 10.0.0.1 port 22 ssh2"
    res2 = parse_line(line2)
    assert res2["type"] == "accepted_password"
    assert res2["username"] == "root"
    assert parse_line("invalid line without IP") is None
def test_get_hour():
    line = "Dec 10 14:07:38 server sshd[1234]: Failed password"
    assert get_hour(line) == 14
    assert get_hour("bad line") is None
def test_repeated_message():
    line="Dec 10 07:07:38 server sshd[1234]: message repeated 3 times: [ Failed password for root from 1.1.1.1 port 22 ssh2 ]"
    res=repeated_message(line)
    assert res==(3, "Failed password for root from 1.1.1.1 port 22 ssh2")
    assert repeated_message("regular log line") is None
def test_calculate_risk():
    ip_data = {
        "failed_password": 30,
        "failed_none": 0,
        "targeted_users": {"root"},
        "root_targeted": True,
        "invalid_users": set(),
        "possible_break_in": False,
        "hourly_data": {},
    }
    risk = calculate_risk(ip_data)
    assert risk["score"] == 4
    assert risk["level"] == "MEDIUM"
    assert "root account targeted" in risk["reasons"]
