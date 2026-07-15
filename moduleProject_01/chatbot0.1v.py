# test/chatbot.py
import os
import json
import sqlite3
from datetime import datetime, timedelta

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI


# .env 파일에 저장된 환경변수를 불러온다.
# 예: OPENAI_API_KEY, OPENAI_MODEL
load_dotenv()

# SQLite DB 파일 경로
DB_PATH = "alerts.db"

# OpenAI API Key와 사용할 모델명을 환경변수에서 가져온다.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# OpenAI Responses API에서 사용할 도구 목록
# Web Search는 대응 권고사항을 작성할 때 최신 보안 대응 지침을 참고하기 위해 사용한다.
# user_location은 검색 결과를 한국 환경에 조금 더 맞추기 위한 설정이다.
tools = [
    {
        "type": "web_search",
        "search_context_size": "medium",
        "user_location": {
            "type": "approximate",
            "country": "KR",
            "city": "Seoul",
            "region": "Seoul",
        }
    }
]


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

    # 테스트용 데이터, 나중에 실제 탐지 엔진과 연동되면 제거해도 된다.
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


def insert_alert(cur, alert):
    """
    Alert JSON 데이터를 alerts 테이블에 저장한다.
    alert_id가 중복되면 INSERT OR IGNORE에 의해 중복 저장되지 않는다.
    """

    # SQL Injection을 막고 타입 처리를 안정적으로 하기 위해 parameter binding을 사용한다.
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

        # 원본 JSON도 문자열 형태로 함께 저장한다.
        # 나중에 컬럼이 추가되더라도 raw_json을 통해 원본 Alert를 확인할 수 있다.
        json.dumps(alert, ensure_ascii=False)
    ))


def get_alerts_between(start_time: datetime, end_time: datetime):
    """
    지정한 시작 시각과 종료 시각 사이의 Alert를 조회한다.
    """

    # SQLite DB에 연결하고, 조회 결과를 dict처럼 다룰 수 있도록 row_factory를 설정한다.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # timestamp가 start_time과 end_time 사이에 있는 Alert만 최신순으로 조회한다.
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

    # sqlite3.Row 객체를 일반 dict 리스트로 변환해서 반환한다.
    return [dict(row) for row in rows]


def get_alert_summary(hours: int):
    """
    최근 N시간 동안의 Alert를 조회하고,
    보고서 생성에 필요한 통계 데이터를 만든다.
    """

    # 분석 종료 시각은 현재 시각, 시작 시각은 현재 시각에서 N시간 전으로 계산한다.
    # 이 값을 프롬프트에 명시해서 LLM이 분석 기간을 임의로 계산하지 않게 한다.
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)

    # 계산된 시간 범위에 해당하는 Alert 목록을 가져온다.
    alerts = get_alerts_between(start_time, end_time)

    # ChatBot 보고서 생성에 사용할 요약 데이터 구조
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

    # Alert 목록을 순회하면서 위험도, 공격 유형, 프로토콜, 탐지 방식, IP, 포트별 개수를 집계한다.
    for alert in alerts:
        risk = alert.get("risk_level") or "UNKNOWN"
        attack = alert.get("attack_type") or "UNKNOWN"
        protocol = alert.get("protocol") or "UNKNOWN"
        detection_type = alert.get("detection_type") or "UNKNOWN"
        src_ip = alert.get("src_ip") or "UNKNOWN"
        dst_port = str(alert.get("dst_port") or "UNKNOWN")

        # dict.get(key, 0) + 1 패턴으로 각 항목의 발생 횟수를 누적한다.
        summary["risk_level_count"][risk] = summary["risk_level_count"].get(risk, 0) + 1
        summary["attack_type_count"][attack] = summary["attack_type_count"].get(attack, 0) + 1
        summary["protocol_count"][protocol] = summary["protocol_count"].get(protocol, 0) + 1
        summary["detection_type_count"][detection_type] = summary["detection_type_count"].get(detection_type, 0) + 1
        summary["top_src_ips"][src_ip] = summary["top_src_ips"].get(src_ip, 0) + 1
        summary["top_dst_ports"][dst_port] = summary["top_dst_ports"].get(dst_port, 0) + 1

    # 요약 통계와 원본 Alert 목록을 함께 반환한다.
    # LLM은 summary로 전체 흐름을 보고, alerts로 개별 이벤트를 확인한다.
    return {
        "summary": summary,
        "alerts": alerts
    }


def extract_hours(user_message: str):
    """
    사용자의 자연어 질문에서 조회 시간 범위를 추출한다.
    예: '최근 3시간 보고서 작성해줘' -> 3
    숫자를 찾지 못하면 기본값 3시간을 사용한다.
    """

    default_hours = 3

    # 간단한 규칙 기반 파싱을 위해 문장을 토큰 단위로 나눈다.
    tokens = (
        user_message
        .replace("동안", " ")
        .replace("최근", " ")
        .replace("시간", " 시간 ")
        .split()
    )

    # 토큰을 순회하면서 시간 숫자를 찾는다.
    for idx, token in enumerate(tokens):
        if token.isdigit():
            return int(token)

        if token.endswith("시간"):
            number = token.replace("시간", "")
            if number.isdigit():
                return int(number)

        if token == "시간" and idx > 0 and tokens[idx - 1].isdigit():
            return int(tokens[idx - 1])

    # 시간 표현이 없으면 기본적으로 최근 3시간을 분석한다.
    return default_hours


def generate_report(user_message: str):
    """
    사용자 질문을 기반으로 SQLite에서 Alert 데이터를 조회하고,
    OpenAI 모델에게 보안 보고서 생성을 요청한다.

    동작 방식:
    1. 사용자가 '최신', '방금', '최근 1건'처럼 말하면 가장 최근 Alert 1건만 조회한다.
    2. 그 외에는 '최근 N시간' 기준으로 Alert 통계와 목록을 조회한다.
    3. 조회한 데이터를 프롬프트에 포함해 모델이 근거 기반으로 답변하게 한다.
    """

    client = OpenAI(api_key=OPENAI_API_KEY)

    # 사용자가 최신 Alert 1건만 요청했는지 판단한다.
    # 이 키워드가 있으면 기간 보고서가 아니라 단일 Alert 상세 분석으로 처리한다.
    latest_one_keywords = [
        "최근 1건",
        "최근 한 건",
        "최근 하나",
        "최근 1개",
        "최신",
        "가장 최근",
        "마지막",
        "방금",
        "최근 발생한",
        "최근 Alert 1건"
    ]

    is_latest_one = any(keyword in user_message for keyword in latest_one_keywords)

    if is_latest_one:
        # 최신 Alert 1건만 조회한다.
        # 단일 이벤트 분석에서는 전체 기간 통계보다 개별 Alert 상세 정보가 더 중요하다.
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 1
        """)

        row = cur.fetchone()
        conn.close()

        # 조회 결과가 있으면 dict로 변환하고, 없으면 None으로 둔다.
        latest_alert = dict(row) if row else None

        # 프롬프트에 넣을 데이터 구조를 단일 Alert 분석용으로 구성한다.
        data = {
            "request_type": "latest_single_alert",
            "alert": latest_alert
        }

        # 최신 1건 분석용 프롬프트
        # 모델이 여러 Alert가 있는 것처럼 말하지 않도록 단일 Alert 기준을 명확히 준다.
        prompt = f"""
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

사용자 요청:
{user_message}

아래는 SQLite에서 조회한 가장 최근 Alert 1건이다.

데이터:
{json.dumps(data, ensure_ascii=False, indent=2)}

다음 형식으로 한국어로 답변해라.

1. 최근 Alert 요약
2. 공격 유형
3. 위험도
4. 출발지 IP / 목적지 IP
5. 대상 포트
6. 탐지 방식
7. 탐지 설명
8. 대응 권고사항

주의:
- 반드시 제공된 Alert 1건만 기준으로 답변할 것
- 여러 건이 발생한 것처럼 말하지 말 것
- 분석 기간 보고서처럼 작성하지 말 것
- 데이터에 없는 내용은 추측하지 말 것
- Alert가 없으면 Alert가 없다고 명확히 말할 것
- 대응 권고사항은 attack_type과 dst_port를 기준으로 작성할 것
"""

    else:
        # 기간 기반 보고서 요청으로 판단되면 최근 N시간 Alert를 조회한다.
        hours = extract_hours(user_message)
        data = get_alert_summary(hours)

        # 기간 보고서용 프롬프트
        # start_time/end_time을 명시해서 모델이 분석 기간을 잘못 계산하지 않게 한다.
        prompt = f"""
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

사용자 요청:
{user_message}

분석 기준 시각:
- 시작 시각: {data["summary"]["start_time"]}
- 종료 시각: {data["summary"]["end_time"]}
- 분석 범위: 최근 {hours}시간

아래는 해당 분석 기간 동안 SQLite에서 조회한 Alert 데이터다.

데이터:
{json.dumps(data, ensure_ascii=False, indent=2)}

다음 형식으로 한국어 보안 보고서를 작성해라.

1. 분석 기간
2. 전체 Alert 요약
3. 위험도별 분포
4. 공격 유형별 분포
5. 탐지 방식별 분포
6. 주요 공격 출발지 IP
7. 주요 대상 포트
8. 주요 위험 이벤트
9. 대응 권고사항

주의:
- 분석 기간은 반드시 위의 시작 시각과 종료 시각을 그대로 사용해 작성할 것
- 현재 시각이나 분석 기간을 임의로 계산하지 말 것
- 데이터에 없는 내용은 추측하지 말 것
- Alert가 없으면 Alert가 없다고 명확히 말할 것
- description 필드가 있으면 주요 위험 이벤트 설명에 반영할 것
- 대응 권고는 실무적으로 간단명료하게 작성할 것
"""

    # Responses API를 호출해 최종 답변을 생성한다.
    # tools에는 Web Search가 포함되어 있어 모델이 필요할 때 대응 방안을 검색할 수 있다.
    response = client.responses.create(
        model=MODEL,
        tools=tools,
        input=prompt
    )

    # 모델이 생성한 텍스트만 Streamlit 화면에 출력한다.
    return response.output_text


# 앱 시작 시 DB를 초기화한다.
init_db()

# Streamlit 페이지 기본 설정
st.set_page_config(page_title="IDS ChatBot MVP", layout="wide")

# 화면 상단 제목
st.title("ChatBot Test")

# API Key가 없으면 앱 실행을 중단한다.
if not OPENAI_API_KEY:
    st.error(".env 파일에 OPENAI_API_KEY를 설정해주세요.")
    st.stop()

# Streamlit 세션에 채팅 기록 저장 공간을 만든다.
# Streamlit은 입력 때마다 스크립트를 다시 실행하므로, session_state에 대화 기록을 보관한다.
if "messages" not in st.session_state:
    st.session_state.messages = []

# 사이드바에는 사용자가 테스트할 수 있는 예시 질문을 표시한다.
with st.sidebar:
    st.caption("예시 질문")
    st.code("최근 3시간 동안의 트래픽 기반으로 보고서 작성해줘")
    st.code("최근 1시간 Alert 요약해줘")
    st.code("최근 6시간 주요 공격 IP 알려줘")

# 기존 채팅 기록을 화면에 다시 렌더링한다.
# 새 입력이 들어와도 이전 대화가 사라지지 않게 하기 위한 처리다.
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# 사용자 입력창
user_input = st.chat_input("예: 최근 3시간 동안의 트래픽 기반으로 보고서 작성해줘")

# 사용자가 메시지를 입력했을 때 실행되는 처리 흐름
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
        with st.spinner("SQLite Alert 데이터를 조회하고 보고서를 작성하는 중..."):
            try:
                # DB 조회 + LLM 보고서 생성을 수행한다.
                answer = generate_report(user_input)
                st.write(answer)
            except Exception as e:
                # API 오류, DB 오류 등이 발생하면 화면에 오류 메시지를 표시한다.
                answer = f"보고서 생성 중 오류가 발생했습니다: {e}"
                st.error(answer)

    # Assistant 응답도 세션 기록에 저장해서 새로고침 전까지 유지한다.
    st.session_state.messages.append({
        "role": "assistant",
        "content": answer
    })
