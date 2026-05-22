# 코드 리뷰 리포트

- **총 검사 라인 수:** 263줄
- **검사 도구:** Amazon Bedrock (Claude 4.5 Sonnet)
- **기반 문서:** PEP8 가이드라인 & OWASP Top 10
- **저장 위치:** /content/drive/MyDrive/my_project_folder/project_review_report.md

---

## app.py (263줄)

### 스타일 검사
PEP8 및 일반적인 스타일 규칙 위반 목록입니다:

**공백 및 연산자 관련**
- [23] 연산자 주변 공백 부족: `conn=sqlite3.connect(db_path)` → `conn = sqlite3.connect(db_path)`
- [24] 연산자 주변 공백 부족: `cursor =conn.cursor()` → `cursor = conn.cursor()`

**라인 길이 관련**
- [70] 라인 길이 초과 (79자 이상): `if len(password) < self.min_password_length: return {...}` — 조건문과 반환문을 한 줄에 작성
- [79] 라인 길이 초과 (79자 이상): SQL 쿼리 문자열 결합으로 인한 극도로 긴 한 줄
- [101] 라인 길이 초과: f-string SQL 쿼리가 한 줄에 작성됨
- [145] 라인 길이 초과: `if len(title) > self.max_title_length: return {...}` — 조건문과 반환문을 한 줄에 작성

**함수/클래스 간격 관련**
- [59] (UserManagement 클래스 시작 전) 최상위 클래스 정의 앞에 빈 줄 2개가 없음
- [131] (PostManager 클래스 시작 전) 최상위 클래스 정의 앞에 빈 줄 2개가 없음
- [177] (`유틸리티_시스템_체크` 함수 정의 전) 최상위 함수 정의 앞 빈 줄 2개 규칙 미준수

**불필요한 공백 줄 관련**
- [135~136] `__init__` 메서드 내부에 의미 없는 연속 빈 줄 2개 존재

**네이밍 규칙 관련**
- [120] 한글 메서드명 사용: `def 비밀번호_변경_시스템(...)` — PEP8은 ASCII 문자(snake_case) 사용 권장
- [177] 한글 함수명 사용: `def 유틸리티_시스템_체크()` — PEP8 네이밍 규칙 위반
- [183] 한글 함수명 및 한글 매개변수명 사용: `def 임시_비밀번호_생성기(길이)` — PEP8 규칙 위반
- [192] 한글 함수명 사용: `def 데이터_인코딩_도구(plain_text)` — PEP8 규칙 위반

**import 위치 관련**
- [185] 함수 내부에서 `import random` 수행 — PEP8은 모든 import를 파일 최상단에 위치시킬 것을 권장

**미사용 변수 관련**
- [193] 미사용 변수 선언: `dummy_val = "Unused configuration data"` — 사용되지 않는 변수 방치

**상수/전역 변수 관련**
- [11~12] 전역 변수 `db_path`, `log_file_path`가 소문자 snake_case로 선언되어 있으나, 모듈 수준의 설정 상수는 `UPPER_SNAKE_CASE`로 선언하는 것이 일반적 관례에 부합함

### 보안 검사
### 파트 1
코드에서 발견된 보안 취약점 목록입니다:

---

## 🔴 취약점 1: 민감한 자격 증명 하드코딩 (Hardcoded Credentials)

- **위치**: 전역 변수 선언부 (`SECRET_KEY`, `AWS_FAKE_KEY`, `AWS_FAKE_SECRET`)
- **유형**: A02 – Cryptographic Failures / 민감 정보 노출
- **심각도**: 🔴 **Critical**
- **설명**: API 키, 시크릿 키 등 민감한 자격 증명이 소스코드에 직접 하드코딩되어 있음. 소스코드가 노출될 경우 즉시 악용 가능.
- **수정 제안**:
  - 환경 변수(`os.environ.get("SECRET_KEY")`) 또는 `.env` 파일(python-dotenv 라이브러리) 사용
  - AWS Secrets Manager, HashiCorp Vault 등 비밀 관리 도구 활용
  - `.gitignore`에 민감 파일 등록 필수

---

## 🔴 취약점 2: SQL Injection

- **위치**: `login_user()` 함수 및 `register_user()` 함수의 쿼리 생성 부분
- **유형**: A03 – Injection (SQL Injection)
- **심각도**: 🔴 **Critical**
- **설명**: 사용자 입력값을 파라미터 바인딩 없이 문자열로 직접 쿼리에 삽입하고 있음. 예를 들어 `username`에 `' OR '1'='1` 입력 시 인증 우회 가능.
  ```python
  # 취약한 코드 예시
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
  ```
- **수정 제안**:
  ```python
  # 안전한 코드: 파라미터 바인딩 사용
  query = "SELECT * FROM users WHERE username = ? AND password = ?"
  cursor.execute(query, (username, hashed_password))
  ```

---

## 🟠 취약점 3: 취약한 비밀번호 해싱 알고리즘 (MD5)

- **위치**: `register_user()` 및 `login_user()` 함수
- **유형**: A02 – Cryptographic Failures
- **심각도**: 🟠 **High**
- **설명**: MD5는 이미 크래킹이 용이한 알고리즘으로, Rainbow Table 공격 및 Brute Force 공격에 취약함. Salt도 적용되지 않아 동일 비밀번호는 동일 해시 생성.
  ```python
  # 취약한 코드
  hashed_password = hashlib.md5(password.encode()).hexdigest()
  ```
- **수정 제안**:
  ```python
  import bcrypt
  # 등록 시
  hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
  # 검증 시
  bcrypt.checkpw(password.encode(), stored_hash)
  ```
  또는 `hashlib.pbkdf2_hmac`, `argon2` 사용 권장

---

## 🟡 취약점 4: 지나치게 짧은 최소 비밀번호 길이

- **위치**: `UserManagement.__init__()` → `self.min_password_length = 4`
- **유형**: A07 – Identification and Authentication Failures
- **심각도**: 🟡 **Medium**
- **설명**: 최소 비밀번호 길이가 4자로 설정되어 있어 Brute Force 공격에 매우 취약함.
- **수정 제안**: 최소 12자 이상으로 설정하고, 대소문자·숫자·특수문자 포함 정책 추가

---

## 🟡 취약점 5: 예외 처리 시 상세 에러 메시지 노출

- **위치**: `register_user()` 함수의 `except` 블록
- **유형**: A05 – Security Misconfiguration / 정보 노출
- **심각도**: 🟡 **Medium**
- **설명**: DB 오류 메시지를 그대로 출력하여 공격자에게 내부 구조 정보를 노출할 수 있음.
  ```python
  print("Error registered user: " + str(e))  # 위험
  ```
- **수정 제안**: 사용자에게는 일반적인 오류 메시지를 반환하고, 상세 로그는 서버 내부 로그에만 기록

---

## 요약 테이블

| # | 취약점 | 위치 | 심각도 | OWASP |
|---|--------|------|--------|-------|
| 1 | 자격 증명 하드코딩 | 전역 변수 | 🔴 Critical | A02 |
| 2 | SQL Injection | login_user / register_user | 🔴 Critical | A03 |
| 3 | MD5 취약 해싱 | register_user / login_user | 🟠 High | A02 |
| 4 | 짧은 비밀번호 정책 | __init__ | 🟡 Medium | A07 |
| 5 | 에러 메시지 노출 | register_user | 🟡 Medium | A05 |

### 파트 2
코드에서 발견된 보안 취약점 목록입니다.

---

## 1. SQL Injection (심각도: 🔴 매우 높음)

**위치:** `비밀번호_변경_시스템`, `create_post`, `search_posts`, `delete_post` 함수

**유형:** A03:2021 – Injection

**문제:** f-string으로 사용자 입력을 SQL 쿼리에 직접 삽입하고 있어, 악의적인 입력으로 DB 조작이 가능합니다.

```python
# 취약한 코드 예시
query = f"UPDATE users SET password='{new_hashed}' WHERE username='{username}'"
query = f"INSERT INTO posts ... VALUES ('{title}', '{content}', ...)"
query = f"SELECT * FROM posts WHERE title LIKE '%{keyword}%'"
query = f"DELETE FROM posts WHERE id = {post_id}"
```

**수정 제안:** 파라미터 바인딩(Parameterized Query) 사용

```python
# 수정된 코드 예시
query = "UPDATE users SET password=? WHERE username=? AND password=?"
cursor.execute(query, (new_hashed, username, old_hashed))

query = "SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?"
cursor.execute(query, (f"%{keyword}%", f"%{keyword}%"))
```

---

## 2. 하드코딩된 관리자 토큰 (심각도: 🔴 매우 높음)

**위치:** `get_all_users_dangerously` 함수

**유형:** A07:2021 – Identification and Authentication Failures

**문제:** 관리자 인증을 소스코드에 하드코딩된 문자열 비교로 처리하고 있어, 코드가 노출되면 즉시 인증 우회가 가능합니다.

```python
# 취약한 코드
if admin_token == "admin_master_token_2026":
```

**수정 제안:** 환경 변수 또는 안전한 토큰 저장소(예: Secrets Manager) 활용 및 안전한 비교 함수 사용

```python
import hmac, os
expected_token = os.environ.get("ADMIN_TOKEN")
if hmac.compare_digest(admin_token, expected_token):
```

---

## 3. 취약한 해시 알고리즘 MD5 사용 (심각도: 🔴 높음)

**위치:** `비밀번호_변경_시스템` 함수

**유형:** A02:2021 – Cryptographic Failures

**문제:** MD5는 이미 크래킹이 용이한 알고리즘으로, 비밀번호 해싱에 사용하면 레인보우 테이블 공격에 취약합니다.

```python
# 취약한 코드
old_hashed = hashlib.md5(old_password.encode()).hexdigest()
```

**수정 제안:** bcrypt, argon2, 또는 `hashlib.pbkdf2_hmac` 등 Salt가 포함된 강력한 해시 알고리즘 사용

```python
import bcrypt
hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
```

---

## 4. 민감 정보 로그 노출 (심각도: 🟠 높음)

**위치:** 로그인 쿼리 실행 직전 `print` 문, `search_posts`의 `log_query`

**유형:** A09:2021 – Security Logging and Monitoring Failures

**문제:** SQL 쿼리 및 검색 키워드를 로그에 그대로 출력하면 비밀번호, 개인정보 등 민감 데이터가 로그에 노출될 수 있습니다.

```python
# 취약한 코드
print(f"[LOG] 로그인 시도 쿼리 실행: {query}")
log_query = f"INSERT INTO logs ... '검색 수행 키워드: {keyword}'"
```

**수정 제안:** 민감 정보(쿼리 내 파라미터 값 등)는 로그에서 제외하고, 마스킹 처리 후 기록

```python
print("[LOG] 로그인 시도 쿼리 실행됨")  # 쿼리 내용 미포함
```

---

## 5. 권한 검증 미흡 (심각도: 🟠 중간~높음)

**위치:** `delete_post` 함수

**유형:** A01:2021 – Broken Access Control

**문제:** `role` 값을 클라이언트로부터 입력받는 구조라면, 일반 사용자가 `role='admin'`으로 위장하여 타인의 게시글을 삭제할 수 있습니다.

```python
# 취약한 코드
def delete_post(self, post_id, username, role):
    if role == 'admin':
        query = f"DELETE FROM posts WHERE id = {post_id}"
```

**수정 제안:** `role` 값을 클라이언트 입력이 아닌 서버 세션 또는 DB에서 직접 조회하여 검증

```python
# role을 DB에서 조회하여 서버 측에서 결정
cursor.execute("SELECT role FROM users WHERE username=?", (username,))
role = cursor.fetchone()[0]
```

---

## PEP 8 스타일 위반 (심각도: 🟡 낮음, 유지보수성 문제)

| 위치 | 문제 |
|------|------|
| `비밀번호_변경_시스템`, `유틸리티_시스템_체크`, `임시_비밀번호_생성기` | 한글 함수명 사용 (PEP 8: snake_case 영문 권장) |
| `PostManager.__init__` | 불필요한 연속 공백 라인 |
| `create_post` | 한 줄에 `if` + `return` 작성 (가독성 저하) |
| `delete_post`, 전역 함수 | 함수 간 2줄 공백 미준수 |

**수정 제안:** 함수명은 영문 snake_case로 변경, PEP 8 들여쓰기 및 공백 규칙 준수

```python
# 수정 예시
def change_password(self, username, old_password, new_password):
    ...

def utility_system_check():
    ...
```

### 파트 3
코드에서 발견된 보안 취약점 및 코드 품질 문제는 다음과 같습니다.

---

## 🔴 취약점 1: 약한 난수 생성기 사용 (Cryptographic Failures)

- **위치**: `임시_비밀번호_생성기` 함수 내 `random.choice(chars)`
- **유형**: A02:2021 – Cryptographic Failures
- **심각도**: 높음 (High)
- **설명**: `random` 모듈은 보안 목적의 난수 생성에 적합하지 않습니다. 예측 가능한 난수를 생성하므로 비밀번호 생성에 사용하면 안 됩니다.
- **수정 제안**: `secrets` 모듈의 `secrets.choice(chars)`를 사용하세요.
```python
import secrets
pwd += secrets.choice(chars)
```

---

## 🔴 취약점 2: SQL 인젝션 위험 (Injection)

- **위치**: `post_service.search_posts(mock_search_keyword)` 및 `user_service.login_user(...)` 호출부
- **유형**: A03:2021 – Injection
- **심각도**: 높음 (High)
- **설명**: 검색 키워드(`simulation_sql_union_injection_keyword`)와 로그인 입력값이 SQL 쿼리에 직접 삽입될 경우, SQL 인젝션 공격에 취약합니다. 코드 주석에서도 "취약한 검색 필터링"이라고 명시하고 있습니다.
- **수정 제안**: Parameterized Query(준비된 쿼리) 또는 ORM을 사용하여 입력값을 바인딩하세요.
```python
cursor.execute("SELECT * FROM posts WHERE title LIKE ?", ('%' + keyword + '%',))
```

---

## 🟠 취약점 3: Base64는 암호화가 아님 (Cryptographic Failures)

- **위치**: `데이터_인코딩_도구` 함수
- **유형**: A02:2021 – Cryptographic Failures
- **심각도**: 중간 (Medium)
- **설명**: Base64는 단순 인코딩이며, 암호화가 아닙니다. 민감한 데이터를 Base64로 처리하면 누구나 쉽게 디코딩할 수 있어 데이터 보호 효과가 없습니다.
- **수정 제안**: 민감 데이터 보호가 필요하다면 `cryptography` 라이브러리의 AES 등 실제 암호화 알고리즘을 사용하세요.

---

## 🟠 취약점 4: 취약한 비밀번호 사용

- **위치**: `user_service.register_user("admin", "admin1234!", ...)`
- **유형**: A07:2021 – Identification and Authentication Failures
- **심각도**: 중간 (Medium)
- **설명**: `admin/admin1234!`와 같은 예측하기 쉬운 자격증명을 사용하고 있습니다. 실제 운영 환경에 반영될 경우 계정 탈취 위험이 있습니다.
- **수정 제안**: 강력한 비밀번호 정책을 적용하고, 테스트용 자격증명은 환경 변수나 시크릿 관리 도구를 통해 주입하세요.

---

## 🟡 코드 품질 문제 (PEP 8 위반)

- **위치**: 함수명(`임시_비밀번호_생성기`, `데이터_인코딩_도구`), 함수 내부 `import random`
- **유형**: 코드 스타일 위반
- **심각도**: 낮음 (Low)
- **설명**:
  - 함수명은 PEP 8에 따라 `snake_case` (영문)로 작성해야 합니다.
  - `import`문은 파일 최상단에 위치해야 하며, 함수 내부 import는 피해야 합니다.
  - `dummy_val`과 같은 미사용 변수는 제거해야 합니다.
- **수정 제안**:
```python
# 상단에 import 배치
import random
import base64

def generate_temp_password(length):  # 영문 snake_case
    ...

def encode_data(plain_text):  # 영문 snake_case, 미사용 변수 제거
    ...
```

---

## 📋 요약

| # | 취약점 | 위치 | OWASP | 심각도 |
|---|--------|------|-------|--------|
| 1 | 약한 난수 생성기 | `random.choice()` | A02 | 🔴 High |
| 2 | SQL 인젝션 | `search_posts`, `login_user` | A03 | 🔴 High |
| 3 | Base64 오용 | `데이터_인코딩_도구` | A02 | 🟠 Medium |
| 4 | 취약한 자격증명 | `register_user("admin",...)` | A07 | 🟠 Medium |
| 5 | PEP 8 스타일 위반 | 전반 | - | 🟡 Low |

---
