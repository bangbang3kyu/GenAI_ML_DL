# test/chatbot.py
import os
import json
import sqlite3
from datetime import datetime, timedelta

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI


# .env 파일에 저장된 환경변수를 불러온다.
# 예: OPENAI_API_KEY, OPENAI_MODEL, OPENAI_WEB_SEARCH_TOOL
load_dotenv()

# SQLite DB 파일 경로
DB_PATH = "alerts.db"

# OpenAI API Key와 사용할 모델명을 환경변수에서 가져온다.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 기본 모델은 gpt-4.1-mini를 사용한다.
# .env에 OPENAI_MODEL 값을 지정하면 다른 모델로 교체할 수 있다.
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Web Search 도구 타입은 SDK/계정 환경에 따라 다를 수 있다.
# 오류가 나면 .env에 OPENAI_WEB_SEARCH_TOOL=web_search_preview 또는 web_search 로 바꿔서 테스트한다.
WEB_SEARCH_TOOL = os.getenv("OPENAI_WEB_SEARCH_TOOL", "web_search_preview")


# Responses API에 등록할 tool 목록
# function 타입 도구는 모델이 직접 실행하지 않고, Python 코드가 대신 실행해 결과를 돌려준다.
# web_search는 OpenAI가 처리하는 내장 도구로, 대응 권고사항 작성 시 최신 자료 검색에 사용한다.
tools = [
    {
        "type": "function",
        "name": "get_latest_alerts",
        "description": "SQLite DB에서 가장 최근에 발생한 Alert N건을 조회한다. 사용자가 '최근 3건', '최근 5개', '최신 10건'처럼 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "조회할 최근 Alert 개수. 기본값은 3이다."
                }
            },
            "required": ["limit"],
            "additionalProperties": False
        }
    },
    {
        "type": "function",
        "name": "get_alert_summary",
        "description": "SQLite DB에서 최근 N시간 동안의 Alert 목록과 요약 통계를 조회한다. 사용자가 '최근 3시간 보고서', '최근 1시간 요약'처럼 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "조회할 시간 범위. 예: 최근 3시간이면 3."
                }
            },
            "required": ["hours"],
            "additionalProperties": False
        }
    },
    {
        "type": WEB_SEARCH_TOOL,
        "search_context_size": "medium",
        "user_location": {
            "type": "approximate",
            "country": "KR",
            "city": "Seoul",
            "region": "Seoul"
        }
    },
    {
        "type": "function",
        "name": "get_alerts_by_type",
        "description": "SQLite DB에서 특정 공격 유형에 해당하는 Alert를 최신순으로 조회한다. 사용자가 'SSH Brute Force만 보여줘', 'Web Attack 공격 조회해줘', 'HTTP Flood 대응 방안 알려줘'처럼 공격 유형을 기준으로 요청할 때 사용한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "attack_type": {
                    "type": "string",
                    "description": "조회할 공격 유형. 예: SSH Brute Force, Web Attack, HTTP Flood"
                },
                "limit": {
                    "type": "integer",
                    "description": "조회할 최대 Alert 개수. 기본값은 10이다."
                }
            },
            "required": ["attack_type", "limit"],
            "additionalProperties": False
        }
    }
]

# DB 초기화용
def init_db():
    """
    Alert 데이터를 저장할 SQLite DB와 alerts 테이블을 초기화한다.
    테이블이 없으면 새로 만들고, 데이터가 비어 있으면 테스트용 샘플 Alert를 삽입한다.
    """

    # SQLite DB에 연결한다. 파일이 없으면 자동으로 생성된다.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Alert 저장용 테이블 생성
    # raw_json은 원본 Alert JSON 전체를 보존하기 위한 컬럼이다.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        attack_type TEXT,
        risk_level TEXT,
        confidence REAL,
        detection_type TEXT,
        description TEXT,
        raw_json TEXT
    )
    """)

    # 현재 alerts 테이블에 데이터가 몇 개 있는지 확인한다.
    cur.execute("SELECT COUNT(*) FROM alerts")
    count = cur.fetchone()[0]

    # 테스트용 샘플 데이터
    # 실제 프로젝트에서는 탐지 엔진이 생성한 Alert JSON이 이 테이블에 저장된다.
    if count == 0:
        sample_alerts = [
            {
                "alert_id": "model-b7e5d234",
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.0.10",
                "src_port": 44521,
                "dst_port": 8080,
                "protocol": "TCP",
                "attack_type": "Web Attack",
                "risk_level": "MEDIUM",
                "confidence": 0.76,
                "detection_type": "Model",
                "description": "비정상적인 HTTP 요청 패턴 감지"
            },
            {
                "alert_id": "rule-9a12c442",
                "timestamp": (datetime.now() - timedelta(minutes=25)).isoformat(timespec="seconds"),
                "src_ip": "192.168.0.25",
                "dst_ip": "192.168.0.10",
                "src_port": 51244,
                "dst_port": 22,
                "protocol": "TCP",
                "attack_type": "SSH Brute Force",
                "risk_level": "HIGH",
                "confidence": 0.94,
                "detection_type": "Rule + Model",
                "description": "SSH 포트에 대한 반복적인 접속 시도 감지"
            },
            {
                "alert_id": "model-f3c82a10",
                "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds"),
                "src_ip": "192.168.0.44",
                "dst_ip": "192.168.0.10",
                "src_port": 50211,
                "dst_port": 80,
                "protocol": "TCP",
                "attack_type": "HTTP Flood",
                "risk_level": "HIGH",
                "confidence": 0.91,
                "detection_type": "Model",
                "description": "짧은 시간 동안 과도한 HTTP 요청 발생"
            }
        ]

        # 샘플 Alert를 DB에 삽입한다.
        for alert in sample_alerts:
            insert_alert(cur, alert)

    # DB 변경 사항을 저장하고 연결을 닫는다.
    conn.commit()
    conn.close()

# DB 삽입용
def insert_alert(cur, alert):
    """
    Alert JSON 데이터를 alerts 테이블에 저장한다.
    alert_id가 중복되면 INSERT OR IGNORE에 의해 중복 저장되지 않는다.
    """

    # SQL Injection 방지와 타입 안정성을 위해 parameter binding을 사용한다.
    cur.execute("""
    INSERT OR IGNORE INTO alerts (
        alert_id,
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack_type,
        risk_level,
        confidence,
        detection_type,
        description,
        raw_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("alert_id"),
        alert.get("timestamp"),
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("src_port"),
        alert.get("dst_port"),
        alert.get("protocol"),
        alert.get("attack_type"),
        alert.get("risk_level"),
        alert.get("confidence"),
        alert.get("detection_type"),
        alert.get("description"),

        # 원본 Alert JSON을 문자열로 저장한다.
        # 나중에 컬럼 구조가 바뀌어도 raw_json으로 원본 데이터를 확인할 수 있다.
        json.dumps(alert, ensure_ascii=False)
    ))

# get_alert_summary 내부에서 쓰는 보조 함수
def get_alerts_between(start_time: datetime, end_time: datetime):
    """
    지정한 시작 시각과 종료 시각 사이의 Alert를 조회한다.
    get_alert_summary 내부에서 사용하는 보조 함수다.
    """

    # row_factory를 sqlite3.Row로 설정하면 조회 결과를 dict처럼 다룰 수 있다.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 지정한 시간 범위에 포함되는 Alert를 최신순으로 조회한다.
    cur.execute("""
    SELECT *
    FROM alerts
    WHERE timestamp BETWEEN ? AND ?
    ORDER BY timestamp DESC
    """, (
        start_time.isoformat(timespec="seconds"),
        end_time.isoformat(timespec="seconds")
    ))

    rows = cur.fetchall()
    conn.close()

    # sqlite3.Row 객체를 일반 dict 리스트로 변환한다.
    return [dict(row) for row in rows]

# 최근 N건 Alert 조회
def get_latest_alerts(limit: int = 3):
    """
    가장 최근에 발생한 Alert N건을 조회한다.
    Function Calling에서 '최근 3건', '최근 5개' 같은 요청을 처리한다.
    """

    # 지나치게 큰 조회를 막기 위해 1~50 사이로 제한한다.
    limit = max(1, min(int(limit), 50))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # timestamp 기준 최신순으로 N건만 조회한다.
    cur.execute("""
    SELECT *
    FROM alerts
    ORDER BY timestamp DESC
    LIMIT ?
    """, (limit,))

    rows = cur.fetchall()
    conn.close()

    return {
        "request_type": "recent_alerts",
        "limit": limit,
        "alerts": [dict(row) for row in rows]
    }

# 최근 N시간 보고서/요약
def get_alert_summary(hours: int = 3):
    """
    최근 N시간 동안의 Alert를 조회하고,
    보고서 생성에 필요한 통계 데이터를 생성한다.
    Function Calling에서 '최근 3시간 보고서', '최근 1시간 요약' 같은 요청을 처리한다.
    """

    # 조회 범위가 너무 커지는 것을 막기 위해 1~24시간으로 제한한다.
    hours = max(1, min(int(hours), 24))

    # 분석 기준 시간을 Python에서 직접 계산한다.
    # LLM이 임의로 분석 기간을 계산하지 않도록 start_time/end_time을 결과에 포함한다.
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)

    alerts = get_alerts_between(start_time, end_time)

    # LLM이 보고서를 작성할 때 사용할 요약 통계 구조
    summary = {
        "hours": hours,
        "start_time": start_time.isoformat(timespec="seconds"),
        "end_time": end_time.isoformat(timespec="seconds"),
        "total_alerts": len(alerts),
        "risk_level_count": {},
        "attack_type_count": {},
        "protocol_count": {},
        "detection_type_count": {},
        "top_src_ips": {},
        "top_dst_ports": {}
    }

    # Alert 목록을 순회하며 위험도, 공격 유형, 프로토콜, 탐지 방식, IP, 포트별 통계를 누적한다.
    for alert in alerts:
        risk = alert.get("risk_level") or "UNKNOWN"
        attack = alert.get("attack_type") or "UNKNOWN"
        protocol = alert.get("protocol") or "UNKNOWN"
        detection_type = alert.get("detection_type") or "UNKNOWN"
        src_ip = alert.get("src_ip") or "UNKNOWN"
        dst_port = str(alert.get("dst_port") or "UNKNOWN")

        summary["risk_level_count"][risk] = summary["risk_level_count"].get(risk, 0) + 1
        summary["attack_type_count"][attack] = summary["attack_type_count"].get(attack, 0) + 1
        summary["protocol_count"][protocol] = summary["protocol_count"].get(protocol, 0) + 1
        summary["detection_type_count"][detection_type] = summary["detection_type_count"].get(detection_type, 0) + 1
        summary["top_src_ips"][src_ip] = summary["top_src_ips"].get(src_ip, 0) + 1
        summary["top_dst_ports"][dst_port] = summary["top_dst_ports"].get(dst_port, 0) + 1

    return {
        "request_type": "alert_summary",
        "summary": summary,
        "alerts": alerts
    }

# 공격 유형별 Alert 조회
def get_alerts_by_type(attack_type: str, limit: int = 10):
    """
    특정 공격 유형에 해당하는 Alert를 최신순으로 조회한다. (default 10개, 변경 가능)
    Function Calling에서 'SSH Brute Force만 보여줘', 'Web Attack 조회해줘' 같은 요청을 처리한다.
    """

    # 조회 개수는 1~50 사이로 제한
    limit = max(1, min(int(limit), 50))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # LIKE 검색을 사용해 attack_type이 일부만 일치해도 조회되도록 한다.
    # 예: 'SSH' 입력 시 'SSH Brute Force'도 조회 가능
    cur.execute("""
    SELECT *
    FROM alerts
    WHERE attack_type LIKE ?
    ORDER BY timestamp DESC
    LIMIT ?
    """, (
        f"%{attack_type}%",
        limit
    ))

    rows = cur.fetchall()
    conn.close()

    return {
        "request_type": "alerts_by_type",
        "attack_type": attack_type,
        "limit": limit,
        "alerts": [dict(row) for row in rows]
    }

# tool 연결용
def run_local_tool(tool_name: str, arguments: dict):
    """
    모델이 Function Calling으로 요청한 로컬 함수를 실제 Python 함수에 연결한다.
    여기서 tool name을 보고 알맞은 Python 함수를 호출한다.
    """

    if tool_name == "get_latest_alerts":
        return get_latest_alerts(
            limit=arguments.get("limit", 3)
        )

    if tool_name == "get_alert_summary":
        return get_alert_summary(
            hours=arguments.get("hours", 3)
        )

    if tool_name == "get_alerts_by_type":
        return get_alerts_by_type(
            attack_type=arguments.get("attack_type", ""),
            limit=arguments.get("limit", 10)
        )

    return {
        "error": f"Unknown tool: {tool_name}"
    }

# 메인 실행
def generate_report(user_message: str):
    """
    사용자 질문을 Responses API에 전달하고,
    모델이 필요한 DB 조회 함수를 Function Calling으로 호출하도록 처리한다.

    동작 방식:
    1. 모델이 사용자 질문을 해석한다.
    2. 필요한 경우 get_latest_alerts, get_alert_summary, get_alerts_by_type 중 하나를 function_call로 요청한다.
    3. Python 코드가 SQLite에서 데이터를 조회한다.
    4. 조회 결과를 function_call_output으로 다시 모델에게 전달한다.
    5. 모델이 조회 결과를 기반으로 최종 답변을 생성한다.
    """

    client = OpenAI(api_key=OPENAI_API_KEY)

    # 모델이 어떤 상황에서 어떤 함수를 호출해야 하는지 알려주는 시스템 지침
    # 새로운 기능을 추가하면 이 지침에도 호출 규칙과 출력 형식을 함께 추가하는 것이 좋다.
    # 계속 추가할수록 똑똑해짐
    instructions = """
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

반드시 다음 규칙을 따라라.

1. 사용자가 '최근 N건', '최근 N개', '최신 N건'처럼 개수를 말하면 get_latest_alerts 함수를 호출해라.
2. 사용자가 '최근 N시간', 'N시간 동안', '보고서', '요약'처럼 시간 범위를 말하면 get_alert_summary 함수를 호출해라.
3. 사용자가 개수나 시간을 명확히 말하지 않고 최근 Alert를 물으면 get_latest_alerts(limit=3)을 호출해라.
4. DB에 없는 Alert 탐지 결과는 탐지되지 않았다고 명확히 말해라.
   단, 사용자가 특정 공격 유형을 물어본 경우 해당 공격이 DB에서 탐지되지 않았더라도 Web Search를 사용해 공격 개념, 동작 방식, 주요 피해, 대응 방안을 설명해라.
5. 대응 권고사항을 작성할 때는 attack_type과 dst_port를 기준으로 작성해라.
6. 최신 대응 지침이 필요한 경우 Web Search를 사용해도 된다.
7. Web Search를 사용한 경우 출처를 간단히 언급해라.
8. 사용자가 특정 공격 유형을 언급하며 조회, 분석, 대응 방안을 요청하면 get_alerts_by_type 함수를 호출해라.
   예: SSH Brute Force, Web Attack, HTTP Flood, Port Scan, DDoS
9. get_alerts_by_type 호출 결과 alerts가 빈 리스트이면 다음 형식으로 답변해라.
   - 현재 SQLite Alert DB에서는 해당 공격 유형이 탐지되지 않았다고 말할 것
   - 그러나 Web Search를 통해 해당 공격 유형의 개념과 일반적인 대응 방안을 설명할 것
   - 탐지 결과와 일반 보안 지식을 구분해서 작성할 것

출력 형식:
- 최근 N건 요청이면 각 Alert를 번호별로 정리하고, 마지막에 공통 대응 권고사항을 작성해라.
- 최근 N시간 요청이면 분석 기간, 전체 요약, 위험도별 분포, 공격 유형별 분포, 주요 이벤트, 대응 권고사항 순서로 작성해라.
- 공격 유형별 조회 요청이면 해당 attack_type의 Alert 목록, 공통 패턴, 위험도, 대응 권고사항 순서로 작성해라.
- 공격 유형이 DB에서 탐지되지 않은 경우:
  1. 탐지 여부
  2. 공격 개념
  3. 일반적인 공격 방식
  4. 주요 피해
  5. 대응 방안
  6. 참고 출처
"""

    # 1차 호출: 모델이 사용자 질문을 보고 필요한 도구 호출 여부를 결정한다.
    response = client.responses.create(
        model=MODEL,
        instructions=instructions,
        tools=tools,
        input=user_message
    )

    # 모델이 로컬 함수 도구를 호출하면 function_call_output을 만들어 다시 전달한다.
    # 여러 함수 호출이 연속으로 나올 수 있으므로 최대 5번까지 반복 처리한다.
    for _ in range(5):
        function_outputs = []

        # response.output 안에서 function_call 항목을 찾아 실제 로컬 함수를 실행한다.
        for item in response.output:
            if item.type == "function_call":
                arguments = json.loads(item.arguments or "{}")
                result = run_local_tool(item.name, arguments)

                # 실행 결과는 function_call_output 형식으로 다시 모델에게 전달해야 한다.
                function_outputs.append({
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": json.dumps(result, ensure_ascii=False)
                })

        # 더 이상 함수 호출이 없으면 최종 답변이 생성된 상태로 보고 반복을 종료한다.
        if not function_outputs:
            break

        # 2차 이후 호출: 로컬 함수 실행 결과를 모델에게 전달해 최종 답변 생성을 이어간다.
        response = client.responses.create(
            model=MODEL,
            instructions=instructions,
            tools=tools,
            previous_response_id=response.id,
            input=function_outputs
        )

    return response.output_text


# 앱 시작 시 DB를 초기화한다.
init_db()

# Streamlit 페이지 기본 설정
st.set_page_config(page_title="IDS ChatBot", layout="wide")

# 화면 상단 제목
st.title("ChatBot Test")

# API Key가 없으면 앱 실행을 중단한다.
if not OPENAI_API_KEY:
    st.error(".env 파일에 OPENAI_API_KEY를 설정해주세요.")
    st.stop()

# Streamlit은 입력할 때마다 스크립트를 다시 실행하므로,
# session_state에 채팅 기록을 저장해 이전 대화를 유지한다.
if "messages" not in st.session_state:
    st.session_state.messages = []

# 사이드바에 테스트용 예시 질문을 표시한다.
with st.sidebar:
    st.caption("예시 질문")
    st.code("최근 3건 Alert 보여줘")
    st.code("SSH Brute Force 공격만 보여줘")
    st.code("최근 3시간 동안의 트래픽 기반으로 보고서 작성해줘")
    st.code("최근 1시간 Alert 요약해줘")

# 기존 채팅 기록을 화면에 다시 출력한다.
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# 사용자 입력창
user_input = st.chat_input("질문 사항을 적어주세요.")

# 사용자가 메시지를 입력했을 때 실행되는 메인 처리 흐름
if user_input:
    # 사용자 메시지를 세션 기록에 저장한다.
    st.session_state.messages.append({
        "role": "user",
        "content": user_input
    })

    # 사용자 메시지를 채팅 화면에 출력한다.
    with st.chat_message("user"):
        st.write(user_input)

    # Assistant 응답 생성 영역
    with st.chat_message("assistant"):
        with st.spinner("누구보다 열심히 찾아보는중..."):
            try:
                # Responses API + Function Calling을 통해 답변을 생성한다.
                answer = generate_report(user_input)
                st.write(answer)
            except Exception as e:
                # API 오류, DB 오류, tool 호출 오류 등이 발생하면 화면에 표시한다.
                answer = f"보고서 생성 중 오류가 발생했습니다: {e}"
                st.error(answer)

    # Assistant 응답도 세션 기록에 저장한다.
    st.session_state.messages.append({
        "role": "assistant",
        "content": answer
    })