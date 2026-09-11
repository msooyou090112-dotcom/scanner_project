#!/usr/bin/env python3
"""
웹 보안 스캐너

주의: 반드시 본인이 통제하거나 명시적으로 허가받은 대상에만 사용할 것.
DVWA, WebGoat, bWAPP, Metasploitable 같은 일부러 취약하게 만든
실습 환경에서 테스트하는 것을 권장.

기능
  1) 디렉토리 탐색
  2) 헤더 분석
  3) SQLi 탐지   (크롤러가 찾은 입력점 + 기본 테스트)
  4) XSS 탐지
  5) 위험도 분류
  6) 리포트 출력
  7) 결과 저장(SQLite) + 이메일 알림
"""

import time
import random
import string
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------
# [추가] 허용된 대상만 스캔. 실수로 아무 사이트나 쏘는 것을 코드가 막는다.
#        허락받은 대상이 생기면 여기에 호스트만 추가하면 된다.
#        예) ("localhost", "127.0.0.1", "testphp.vulnweb.com")
ALLOWED_HOSTS = ("localhost", "127.0.0.1")

WORDLIST = [
    "admin", "backup", "login", "config", "test",
    "phpinfo.php", "setup.php", "db", "uploads"
]

DELAY = 0.2
TIMEOUT = 5

# SQLi 탐지 기본 대상: (경로, 파라미터 이름) 목록
# 크롤러가 찾은 GET 입력점이 여기에 '추가'된다.
SQLI_TESTS = [("search", "q")]

# XSS는 크롤링한 form을 대상으로 검사
XSS_PROBE = "<script>alert(1)</script>"

# [추가] 이메일 알림 설정
SEND_EMAIL = False                     # 켜려면 True (send_email 안 계정 정보도 채워야 함)
RECEIVER_EMAIL = "receiver@gmail.com"  # 알림 받을 주소

RISK_LEVELS = {
    "sqli": "High",
    "xss": "High",
    "hidden_dir": "Medium",
    "version_disclosure": "Low",
}


def classify(finding_type):
    """발견 유형을 받아 위험 등급을 반환."""
    return RISK_LEVELS.get(finding_type, "Info")


# ---------------------------------------------------------------------------
# 디렉토리 탐색
# ---------------------------------------------------------------------------
def get_baseline(base_url):
    """존재할 리 없는 랜덤 경로로 '없을 때' 응답을 확인한다."""
    rand = "".join(random.choices(string.ascii_lowercase, k=12))
    url = base_url.rstrip("/") + "/" + rand

    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        return r.status_code, len(r.content)
    except requests.RequestException:
        return None, None


def scan_directories(base_url, wordlist):
    """워드리스트의 각 경로에 접근해 존재하는 디렉토리를 찾는다."""
    print("[*] 디렉토리 탐색 시작...")
    base_status, base_len = get_baseline(base_url)

    found = []

    for path in wordlist:
        url = base_url.rstrip("/") + "/" + path

        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)

            is_found = r.status_code == 200 and (
                base_len is None or len(r.content) != base_len
            )

            if is_found:
                found.append(path)
                print(f"    [+] 발견: {url}  (200 OK, {len(r.content)} bytes)")

        except requests.RequestException as e:
            print(f"    [!] 요청 실패: {url}  ({e})")

        time.sleep(DELAY)

    print(f"[*] 디렉토리 탐색 완료 — {len(found)}개 발견\n")
    return found


# ---------------------------------------------------------------------------
# 헤더 분석
# ---------------------------------------------------------------------------
def analyze_headers(base_url):
    """응답 헤더에서 서버 정보를 추출한다."""
    print("[*] 헤더 분석 시작...")
    disclosures = []

    try:
        r = requests.get(base_url, timeout=TIMEOUT)

        server = r.headers.get("Server")
        powered_by = r.headers.get("X-Powered-By")

        if server:
            print(f"    [i] Server: {server}")
            disclosures.append(("Server", server))
        else:
            print("    [i] Server 헤더 없음")

        if powered_by:
            print(f"    [i] X-Powered-By: {powered_by}")
            disclosures.append(("X-Powered-By", powered_by))

    except requests.RequestException as e:
        print(f"    [!] 헤더 분석 실패: ({e})")

    print(f"[*] 헤더 분석 완료 — 노출 항목 {len(disclosures)}개\n")
    return disclosures


# ---------------------------------------------------------------------------
# SQLi 탐지
# ---------------------------------------------------------------------------
SQL_ERROR_SIGNS = [
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "sqlite3::",
    "pg_query",
]

SQLI_PROBES = ["'", '"', "')"]


def test_sqli(base_url, tests):
    """지정된 (경로, 파라미터)에 프로브를 넣어 SQL 에러가 나는지 확인한다."""
    print("[*] SQLi 탐지 시작...")
    vulnerable = []

    for path, param in tests:
        hit = False

        for probe in SQLI_PROBES:
            url = base_url.rstrip("/") + "/" + path

            try:
                r = requests.get(
                    url,
                    params={param: probe},
                    timeout=TIMEOUT
                )

                body = r.text.lower()

                if any(sign in body for sign in SQL_ERROR_SIGNS):
                    print(
                        f"    [+] SQLi 의심: {url} "
                        f"(param={param}, probe={probe!r})"
                    )
                    vulnerable.append((path, param))
                    hit = True
                    break

            except requests.RequestException as e:
                print(f"    [!] 요청 실패: {url}  ({e})")

            time.sleep(DELAY)

        if not hit:
            print(f"    [-] {path}?{param}= : 취약점 신호 없음")

    print(f"[*] SQLi 탐지 완료 — {len(vulnerable)}개 의심\n")
    return vulnerable


# ---------------------------------------------------------------------------
# 크롤링
# ---------------------------------------------------------------------------
def same_origin(base_url, target_url):
    """기본 URL과 같은 호스트인지 확인한다."""
    base = urlparse(base_url)
    target = urlparse(target_url)

    return (
        target.scheme in ("http", "https")
        and target.netloc == base.netloc
    )


def crawl_pages(base_url, max_pages=20):
    """
    같은 호스트의 페이지를 제한된 수만큼 수집하고 form 정보를 반환한다.
    SQLi/XSS 검사가 함께 사용할 입력 지점을 찾는 역할이다.
    반환: [(url, forms), ...]
    """
    print("[*] 페이지 크롤링 시작...")

    queue = [base_url]
    visited = set()
    pages = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            r = requests.get(url, timeout=TIMEOUT)
            content_type = r.headers.get("Content-Type", "")

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            forms = soup.find_all("form")
            pages.append((url, forms))

            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"]).split("#")[0]

                if (
                    same_origin(base_url, next_url)
                    and next_url not in visited
                    and next_url not in queue
                ):
                    queue.append(next_url)

        except requests.RequestException as e:
            print(f"    [!] 크롤링 실패: {url} ({e})")

        time.sleep(DELAY)

    print(
        f"[*] 페이지 크롤링 완료 — "
        f"{len(visited)}개 URL 확인, {len(pages)}개 HTML 페이지 수집\n"
    )

    return pages


# [추가] 크롤링한 form에서 SQLi 테스트 지점 (경로, 파라미터)을 뽑는 다리
def collect_sqli_targets(base_url, pages):
    """
    크롤링한 페이지의 GET 방식 form에서 SQLi 테스트 지점을 뽑는다.
    test_sqli(base_url, tests)가 그대로 받아 쓸 수 있는 (경로, 파라미터) 형식.
    base_url로 시작하는 주소만 추린다(단순 concat으로 재구성 가능한 것만).
    """
    base = base_url.rstrip("/")
    targets = set()

    for page_url, forms in pages:
        for form in forms:
            method = (form.get("method") or "get").lower()
            if method != "get":
                continue

            action = urljoin(page_url, form.get("action", ""))
            action = action.split("#")[0].split("?")[0]

            if not action.startswith(base):
                continue
            path = action[len(base):].lstrip("/")

            for field in form.find_all(["input", "textarea"]):
                name = field.get("name")
                ftype = (field.get("type") or "").lower()
                if name and ftype not in ("submit", "button", "reset", "file"):
                    targets.add((path, name))

    return list(targets)


# ---------------------------------------------------------------------------
# XSS 탐지
# ---------------------------------------------------------------------------
def test_xss(pages):
    """
    크롤링한 form의 입력값에 XSS 테스트 문자열을 넣고,
    응답에 해당 문자열이 그대로 반사되는지 확인한다.

    이 방식은 '반사된 문자열'을 찾는 기본 탐지이며,
    브라우저에서 실제 JavaScript 실행 여부까지 보장하지는 않는다.
    """
    print("[*] XSS 탐지 시작...")
    vulnerable = []

    for page_url, forms in pages:
        for form in forms:
            method = form.get("method", "get").lower()
            action = urljoin(page_url, form.get("action", ""))

            inputs = form.find_all(["input", "textarea"])
            named_inputs = [
                field for field in inputs
                if field.get("name")
                and field.get("type", "").lower()
                not in ("submit", "button", "reset", "file")
            ]

            for field in named_inputs:
                param = field.get("name")

                data = {}
                for item in named_inputs:
                    data[item.get("name")] = "test"
                data[param] = XSS_PROBE

                try:
                    if method == "post":
                        r = requests.post(
                            action,
                            data=data,
                            timeout=TIMEOUT
                        )
                    else:
                        r = requests.get(
                            action,
                            params=data,
                            timeout=TIMEOUT
                        )

                    if XSS_PROBE.lower() in r.text.lower():
                        print(
                            f"    [+] XSS 의심: {action} "
                            f"(param={param}, method={method.upper()})"
                        )
                        vulnerable.append(
                            (action, param, method.upper())
                        )

                except requests.RequestException as e:
                    print(f"    [!] XSS 요청 실패: {action} ({e})")

                time.sleep(DELAY)

    print(f"[*] XSS 탐지 완료 — {len(vulnerable)}개 의심\n")
    return vulnerable


# ---------------------------------------------------------------------------
# 결과 저장 + 알림  (담당: 팀원 B) — 함수 원본 유지
# ---------------------------------------------------------------------------
def create_database():
    conn = sqlite3.connect("scan_result.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            vulnerability TEXT,
            risk TEXT,
            scan_time TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_log(url, vulnerability, risk):
    conn = sqlite3.connect("scan_result.db")
    cursor = conn.cursor()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO vulnerability_log
        (url, vulnerability, risk, scan_time)
        VALUES (?, ?, ?, ?)
    """, (url, vulnerability, risk, scan_time))

    conn.commit()
    conn.close()


def send_email(receiver_email, url, vulnerability, risk):
    sender_email = "your_email@gmail.com"
    sender_password = "앱비밀번호"

    subject = "취약점 발견 알림"

    message = f"""
취약점이 발견되었습니다.

URL : {url}
취약점 : {vulnerability}
위험도 : {risk}
"""

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.send_message(msg)
    server.quit()


# ---------------------------------------------------------------------------
# 리포트
# ---------------------------------------------------------------------------
def build_report(dirs, disclosures, sqli, xss):
    """발견 항목들을 위험 등급별로 묶어 정리한다."""
    findings = []

    for path, param in sqli:
        findings.append(
            (
                classify("sqli"),
                f"SQL 인젝션 의심: /{path} (파라미터: {param})"
            )
        )

    for action, param, method in xss:
        findings.append(
            (
                classify("xss"),
                f"XSS 의심: {action} "
                f"(파라미터: {param}, 방식: {method})"
            )
        )

    for path in dirs:
        findings.append(
            (
                classify("hidden_dir"),
                f"숨겨진 디렉토리: /{path}"
            )
        )

    for name, value in disclosures:
        findings.append(
            (
                classify("version_disclosure"),
                f"버전/기술 정보 노출: {name}: {value}"
            )
        )

    return findings


def print_report(findings):
    print("=" * 50)
    print(" 스캔 리포트")
    print("=" * 50)

    if not findings:
        print(" 발견된 항목이 없습니다.")
        return

    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}

    for level in sorted(
        set(f[0] for f in findings),
        key=lambda x: order.get(x, 99)
    ):
        items = [desc for lvl, desc in findings if lvl == level]

        print(f"\n[{level}]  ({len(items)}건)")

        for desc in items:
            print(f"  - {desc}")

    print("\n" + "=" * 50)


# ---------------------------------------------------------------------------
# 통합 실행
# ---------------------------------------------------------------------------
def run_scan(target):
    """
    Flask에서 호출하는 통합 스캔 함수.
    """
    target = target.strip()

    if not target:
        raise ValueError("URL이 비어 있습니다.")

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            "URL 형식이 올바르지 않습니다. "
            "http:// 또는 https:// 주소를 입력하세요."
        )

    # [추가] 화이트리스트 검사 — 허용된 호스트가 아니면 스캔 자체를 막는다
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"허용되지 않은 대상입니다: {parsed.hostname} "
            f"(허용 목록: {', '.join(ALLOWED_HOSTS)})"
        )

    print(f"[*] 대상: {target}\n")

    # 크롤링은 한 번만 하고 SQLi / XSS 가 함께 사용
    pages = crawl_pages(target)

    dirs = scan_directories(target, WORDLIST)
    disclosures = analyze_headers(target)

    # [변경] 크롤러가 찾은 GET 입력점을 SQLi 대상에 추가
    sqli_tests = list(set(SQLI_TESTS) | set(collect_sqli_targets(target, pages)))
    sqli = test_sqli(target, sqli_tests)

    # [변경] test_xss가 pages를 직접 받음 (크롤링 중복 제거)
    xss = test_xss(pages)
    xss = list(set(xss))

    findings = build_report(dirs, disclosures, sqli, xss)

    print_report(findings)

    # [추가] 결과를 SQLite에 저장하고, 켜져 있으면 High 위험만 이메일 발송
    create_database()
    for level, desc in findings:
        save_log(target, desc, level)
        if SEND_EMAIL and level == "High":
            try:
                send_email(RECEIVER_EMAIL, target, desc, level)
            except Exception as e:
                print(f"    [!] 이메일 전송 실패: {e}")

    return findings


if __name__ == "__main__":
    # 테스트할 때만 직접 실행
    TARGET = "http://localhost/dvwa"
    run_scan(TARGET)
