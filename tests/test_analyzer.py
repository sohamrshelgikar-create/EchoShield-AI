import pytest

from backend.analyzer import analyze_message

SCAMS = {
    "kyc_otp_link": "Dear customer, your SBI KYC expires today. Share your OTP now: http://bit.ly/sbi-kyc",
    "upi_pin_receive": "Congratulations! To receive Rs 5000 refund, enter your UPI PIN and approve the collect request immediately.",
    "apk_remote": "Your SBI YONO account is blocked. Install SBI_KYC.apk and share your screen via AnyDesk.",
    "digital_arrest": "This is CBI. A digital arrest warrant is issued against you. Do not tell anyone.",
    "cvv_card": "Your card will be blocked. Reply with your card number and CVV within 1 hour.",
    "hinglish": "Aapka account block ho jayega. Turant OTP bhejiye.",
}
BENIGN = {
    "otp_warning": "123456 is your OTP for login. Never share your OTP with anyone.",
    "debit_alert": "HDFC Bank: Rs 500.00 debited from A/c XX1234 on 11-10-26. Not you? Call 1800-202-6161.",
    "casual": "Hey, are we still meeting for lunch tomorrow?",
    "enter_otp_checkout": "Enter OTP 482913 to complete your transaction of Rs 500 at Amazon.",
    "official_link": "HDFC Bank: view your statement at https://www.hdfcbank.com/statements",
}
REQUIRED_KEYS = {"risk_level", "risk_score", "summary", "threat_type", "indicators", "indicator_details",
                 "recommendations", "urls_found", "spoken_summary", "disclaimer"}


@pytest.mark.parametrize("name", SCAMS)
def test_scam_messages_are_high(name):
    r = analyze_message(SCAMS[name])
    assert r["risk_level"] == "HIGH", r["indicators"]
    assert any(d["severity"] == "high" for d in r["indicator_details"])


@pytest.mark.parametrize("name", BENIGN)
def test_benign_messages_are_not_flagged_medium_or_high(name):
    r = analyze_message(BENIGN[name])
    assert r["risk_level"] in ("NONE", "LOW"), r["indicators"]


def test_mentioning_bank_otp_urgent_is_not_automatically_fraud():
    r = analyze_message("Bank notice: your OTP is 551122, it is urgent that you do not share it with anyone.")
    assert r["risk_level"] in ("NONE", "LOW")


def test_weak_signals_alone_never_reach_high():
    r = analyze_message("Dear customer, urgent! Congratulations, claim your reward immediately. Final notice, last chance, today only.")
    assert all(d["severity"] != "high" for d in r["indicator_details"])
    assert r["risk_score"] <= 49 and r["risk_level"] != "HIGH"


def test_none_result_never_claims_safety():
    r = analyze_message("Hey, are we still meeting for lunch tomorrow?")
    assert r["risk_level"] == "NONE"
    assert "does not prove" in r["summary"]
    assert "this message is safe" not in r["summary"].lower() and "no risk" not in r["summary"].lower()
    assert r["indicator_details"] == []


@pytest.mark.parametrize("text", list(SCAMS.values()) + list(BENIGN.values()) + ["x" * 5000, "!!!", "1 2 3", "OTP " * 800])
def test_score_bounds_and_schema(text):
    r = analyze_message(text)
    assert REQUIRED_KEYS <= set(r)
    assert 0 <= r["risk_score"] <= 100
    assert r["risk_level"] in {"NONE", "LOW", "MEDIUM", "HIGH"}
    assert (r["risk_level"] == "NONE") == (r["risk_score"] == 0)
    assert len(r["indicators"]) == len(r["indicator_details"])
    for d in r["indicator_details"]:
        assert set(d) == {"name", "evidence", "severity"} and d["severity"] in ("high", "medium", "low")
    assert r["recommendations"]


def test_shortener_and_look_alike_domain_are_flagged():
    r = analyze_message("Update KYC at http://sbi-secure-login.xyz or https://bit.ly/abc now")
    names = {d["name"] for d in r["indicator_details"]}
    assert "Shortened link" in names and "Suspicious link" in names


def test_brand_with_unrelated_link_is_a_warning_with_honest_wording():
    r = analyze_message("SBI alert: confirm your details at https://example-offers.com/verify")
    d = next(d for d in r["indicator_details"] if d["name"].startswith("Link does not match"))
    assert "not exhaustive" in d["evidence"]


def test_official_domain_is_not_flagged_as_mismatch():
    r = analyze_message(BENIGN["official_link"])
    assert not any(d["name"].startswith("Link does not match") for d in r["indicator_details"])


def test_ip_address_url_is_flagged_high():
    r = analyze_message("Pay now at http://192.168.10.5/pay")
    assert any("raw IP" in d["evidence"] and d["severity"] == "high" for d in r["indicator_details"])


def test_zero_width_characters_do_not_evade_detection():
    r = analyze_message("Share your O\u200bTP and U\u200bPI PIN now")
    # Zero-width characters are stripped before matching
    assert r["risk_level"] in ("MEDIUM", "HIGH")


def test_parcel_and_job_scams_detected():
    parcel = analyze_message("Your parcel is held. Pay the delivery fee at http://india-post-track.xyz/pay within 24 hours")
    assert "parcel" in parcel["threat_type"].lower() and parcel["risk_level"] in ("MEDIUM", "HIGH")
    job = analyze_message("Part time job, work from home, earn daily. Joining fee Rs 500. Join our Telegram group.")
    assert job["risk_level"] in ("MEDIUM", "HIGH") and "job" in job["threat_type"].lower()


def test_urls_found_are_returned_and_not_executed():
    r = analyze_message("see http://a.example/x and www.b.example/y.")
    assert r["urls_found"] == ["http://a.example/x", "www.b.example/y"]


def test_disclaimer_present():
    assert "not proof" in analyze_message("hello there")["disclaimer"]


def test_spoken_summary_is_short_and_plain():
    s = analyze_message(SCAMS["kyc_otp_link"])["spoken_summary"]
    assert len(s) < 400 and "scam" in s.lower()
