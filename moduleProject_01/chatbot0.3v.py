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

# OpenAI API Key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 사용할 OpenAI 모델명
# .env에 OPENAI_MODEL이 없으면 기본값으로 gpt-4.1-mini를 사용한다.
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Web Search 도구명
# Web Search 도구 타입은 SDK/계정 환경에 따라 다를 수 있다.
# 오류가 나면 .env에 OPENAI_WEB_SEARCH_TOOL=web_search_preview 또는 web_search 로 바꿔서 테스트한다.
WEB_SEARCH_TOOL = os.getenv("OPENAI_WEB_SEARCH_TOOL", "web_search_preview")


# Responses API에 등록할 tool 목록
# type=function:
#   모델이 "이 함수가 필요하다"고 판단하면 function_call을 발생시킨다.
#   실제 함수 실행은 Python 코드의 run_local_tool()에서 처리한다.
#
# type=WEB_SEARCH_TOOL:
#   OpenAI가 제공하는 내장 Web Search 도구다.
#   DB에 없는 공격 유형 설명이나 최신 대응 방안 검색에 사용된다.
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

    # SQLite DB에 연결한다. DB 파일이 없으면 자동으로 생성된다.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Alert 저장용 테이블 생성
    # raw_json은 Alert 원본 전체를 보존하기 위한 컬럼이다.
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

    # 현재 DB에 Alert가 몇 건 있는지 확인한다.
    cur.execute("SELECT COUNT(*) FROM alerts")
    count = cur.fetchone()[0]

    # 테스트 환경에서 바로 챗봇을 확인할 수 있도록 샘플 데이터를 넣는다.
    # 실제 탐지 엔진과 연동되면 이 샘플 삽입 부분은 제거하거나 비활성화해도 된다.
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

        # 샘플 Alert들을 DB에 저장한다.
        for alert in sample_alerts:
            insert_alert(cur, alert)

    # DB 변경사항을 저장하고 연결을 종료한다.
    conn.commit()
    conn.close()

# DB 삽입용
def insert_alert(cur, alert):
    """
    Alert JSON 데이터를 alerts 테이블에 저장한다.
    alert_id가 중복되면 INSERT OR IGNORE에 의해 중복 저장되지 않는다.
    """

    # SQL Injection 방지를 위해 문자열 포맷팅 대신 parameter binding을 사용
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
        # 나중에 컬럼 구조가 바뀌어도 raw_json으로 원본 데이터를 확인할 수 있다
        json.dumps(alert, ensure_ascii=False)
    ))

# get_alert_summary 내부에서 쓰는 보조 함수
def get_alerts_between(start_time: datetime, end_time: datetime):
    """
    지정한 시작 시각과 종료 시각 사이의 Alert를 조회한다.
    get_alert_summary() 내부에서 사용하는 보조 함수다.
    """

    # row_factory를 sqlite3.Row로 설정하면 조회 결과를 dict처럼 다룰 수 있다.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 시간 범위에 포함되는 Alert를 최신순으로 조회한다.
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
    Function Calling에서 '최근 3건', '최신 5개' 같은 요청을 처리한다.
    """

    # 너무 많은 데이터를 한 번에 가져오지 않도록 1~50 사이로 제한한다.
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

    # 모델이 결과의 의미를 쉽게 알 수 있도록 request_type을 함께 반환한다.
    return {
        "request_type": "recent_alerts",
        "limit": limit,
        "alerts": [dict(row) for row in rows]
    }

# 최근 N시간 보고서/요약
def get_alert_summary(hours: int = 3):
    """
    최근 N시간 동안의 Alert를 조회하고,
    보고서 생성에 필요한 통계 데이터를 만든다.
    Function Calling에서 '최근 3시간 보고서', '최근 1시간 요약' 같은 요청을 처리한다.
    """

    # 조회 범위를 1~24시간으로 제한
    # 테스트/데모 환경에서 너무 큰 조회가 발생하는 것을 막기 위함
    hours = max(1, min(int(hours), 24))

    # 분석 기간은 LLM이 아니라 Python에서 직접 계산한다.
    # 이렇게 해야 모델이 현재 시각이나 분석 기간을 임의로 틀리게 계산하지 않는다.
    # LLM이 임의로 분석 기간을 계산하지 않도록 start_time/end_time을 결과에 포함한다.
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)

    alerts = get_alerts_between(start_time, end_time)

    # LLM이 보고서를 작성할 때 사용할 요약 통계 구조, 변경 가능
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
    특정 공격 유형에 해당하는 Alert를 최신순으로 조회한다.
    Function Calling에서 'SSH Brute Force만 보여줘', 'Web Attack 조회해줘' 같은 요청을 처리한다.
    """

    # 조회 개수를 1~50 사이로 제한한다.
    limit = max(1, min(int(limit), 50))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # LIKE 검색을 사용해 attack_type 일부만 입력해도 검색되게 한다.
    # 예: attack_type='SSH' -> 'SSH Brute Force'도 검색 가능
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
    Responses API는 함수 호출 의도만 반환한다.
    실제 SQLite 조회는 이 함수에서 tool_name을 기준으로 분기해 실행한다.
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

# 대화 흐름 기억
def build_model_input(user_message: str, previous_context=None, conversation_context=None):
    """
    모델에게 전달할 input을 구성한다.

    conversation_context:
    - 최근 대화 기록이다.
    - '아까 말한 것', '위 내용', '그 답변'처럼 대화 흐름을 가리키는 표현을 이해하는 데 사용한다.

    previous_context:
    - 마지막 Function Calling 결과 원본 데이터다.
    - '그걸', '방금 조회한 Alert', '두 번째 Alert'처럼 특정 DB 조회 결과를 가리키는 표현을 정확히 처리하는 데 사용한다.
    """

    model_input = []

    # 최근 대화 기록을 먼저 넣어 모델이 흐름을 이해할 수 있게 한다.
    if conversation_context:
        for message in conversation_context:
            model_input.append({
                "role": message["role"],
                "content": message["content"]
            })

    # 마지막 DB 조회 결과를 별도 컨텍스트로 넣는다.
    # 일반 대화 기록보다 원본 데이터에 가까우므로 Alert 보고서/재분석에 더 정확하다.
    if previous_context:
        model_input.append({
            "role": "user",
            "content": f"""
이전 DB 조회 결과:
{json.dumps(previous_context, ensure_ascii=False, indent=2)}

사용자가 '그걸', '방금 것', '방금 조회한 Alert', '위 내용', '이 Alert', '두 번째 Alert'처럼 말하면
위 이전 DB 조회 결과를 우선 기준으로 삼아라.
"""
        })

    # 마지막에 현재 사용자 요청을 넣는다.
    model_input.append({
        "role": "user",
        "content": user_message
    })

    return model_input

# 메인 실행
def generate_report(user_message: str, previous_context=None, conversation_context=None):
    """
    사용자 질문을 Responses API에 전달하고,
    모델이 필요한 DB 조회 함수를 Function Calling으로 호출하도록 처리한다.

    동작 방식:
    1. 최근 대화 기록과 마지막 DB 조회 결과를 input에 함께 넣는다.
    2. 모델이 사용자 요청을 해석해 필요한 tool을 function_call로 요청한다.
    3. Python이 run_local_tool()로 실제 SQLite 조회를 수행한다.
    4. 조회 결과를 function_call_output으로 다시 모델에게 전달한다.
    5. 모델이 DB 조회 결과와 대화 흐름을 바탕으로 최종 답변을 작성한다.
    6. 새 DB 조회 결과는 latest_tool_context로 저장되어 다음 질문에서 재사용된다.
    """

    client = OpenAI(api_key=OPENAI_API_KEY)

    # 모델이 어떤 상황에서 어떤 도구를 사용해야 하는지 알려주는 시스템 지침
    instructions = """
너는 실시간 침입 탐지 시스템의 보안 분석 챗봇이다.

반드시 다음 규칙을 따라라.

1. 사용자가 '최근 N건', '최근 N개', '최신 N건'처럼 개수를 말하면 get_latest_alerts 함수를 호출해라.
2. 사용자가 '최근 N시간', 'N시간 동안', '요약'처럼 시간 범위를 말하면 get_alert_summary 함수를 호출해라.
3. 사용자가 '보고서', '리포트', 'Notion 형식', '노션 형식', '문서로 정리'처럼 보고서 작성을 요청하면 관련 함수를 호출한 뒤 Notion Markdown 보고서 형식으로 작성해라.
4. 사용자가 개수나 시간을 명확히 말하지 않고 최근 Alert를 물으면 get_latest_alerts(limit=3)을 호출해라.
5. DB에 없는 Alert 탐지 결과는 탐지되지 않았다고 명확히 말해라.
   단, 사용자가 특정 공격 유형을 물어본 경우 해당 공격이 DB에서 탐지되지 않았더라도 Web Search를 사용해 공격 개념, 동작 방식, 주요 피해, 대응 방안을 설명해라.
6. 대응 권고사항을 작성할 때는 attack_type과 dst_port를 기준으로 작성해라.
7. 최신 대응 지침이 필요한 경우 Web Search를 사용해도 된다.
8. Web Search를 사용한 경우 출처를 간단히 언급해라.
9. 사용자가 특정 공격 유형을 언급하며 조회, 분석, 대응 방안을 요청하면 get_alerts_by_type 함수를 호출해라.
   예: SSH Brute Force, Web Attack, HTTP Flood, Port Scan, DDoS, Ransomware
10. get_alerts_by_type 호출 결과 alerts가 빈 리스트이면 다음 형식으로 답변해라.
   - 현재 SQLite Alert DB에서는 해당 공격 유형이 탐지되지 않았다고 말할 것
   - 그러나 Web Search를 통해 해당 공격 유형의 개념과 일반적인 대응 방안을 설명할 것
   - 탐지 결과와 일반 보안 지식을 구분해서 작성할 것
11. 사용자가 '그걸', '방금 것', '위 내용', '이 Alert', '두 번째 Alert'처럼 이전 내용을 가리키면,
    새로 DB를 조회하기보다 이전 DB 조회 결과와 대화 기록을 우선 기준으로 답변해라.
12. 이전 DB 조회 결과만으로 기준 대상을 확정할 수 없으면, 임의로 추측하지 말고 어떤 Alert를 기준으로 할지 물어봐라.
13. 데이터에 없는 값은 'N/A'로 표시하고, DB에 존재하지 않는 Alert를 만들어내지 마라.

일반 응답 형식:
- 사용자가 단순히 '최근 N건 보여줘', '최근 N개 조회해줘', 'SSH Brute Force 공격만 보여줘'처럼 조회를 요청하면 보고서 형식으로 작성하지 마라.
- 일반 조회 응답은 짧고 읽기 쉽게 bullet 형식으로 작성해라.
- 각 Alert는 번호별로 정리하되, 번호 옆 제목에 alert_id를 반드시 표시해라.
  예: 1. model-b7e5d234
- 각 Alert에는 alert_id, 발생 시각, 공격 유형, 위험도, 출발지 IP, 목적지 IP, 대상 포트, 탐지 방식, 설명을 포함해라.
- alert_id가 없으면 번호 옆에 "N/A"를 표시해라.
- 마지막에 간단한 대응 권고사항을 2~3개만 작성해라.

보고서 작성 형식:
- 사용자가 '보고서', '리포트', 'Notion', '노션', '문서로 정리', '보고서 작성'을 명시적으로 요청한 경우에만 아래 Notion Markdown 템플릿을 사용해라.
- Notion에 있는 이모지, 콜아웃 등을 자유롭게 사용하여 보고서를 작성해라
- 보고서는 Notion에 바로 복사/붙여넣기 가능한 Markdown 형식으로 작성해라.
- 불필요한 인사말, 사족, 코드블록 없이 보고서 본문만 출력해라.

# 침입 탐지 분석 보고서

## 1. 분석 개요
- 분석 기준:
- 분석 대상:
- 조회 범위:
- 전체 Alert 수:

## 2. 핵심 요약
- 주요 공격 유형:
- 최고 위험도:
- 주요 출발지 IP:
- 주요 대상 포트:
- 종합 판단:

## 3. Alert 상세 내역

| No | 발생 시각 | 공격 유형 | 위험도 | 출발지 IP | 목적지 IP | 대상 포트 | 탐지 방식 | 신뢰도 |
|---|---|---|---|---|---|---|---|---|

## 4. 공격 패턴 분석
- 반복적으로 관찰된 패턴:
- 의심되는 공격 목적:
- 관련 위험 포트:
- 추가 확인이 필요한 로그:

## 5. 위험도 평가
- 전체 위험도:
- 판단 근거:
- 우선 대응 대상:

## 6. 대응 권고사항
- [ ] 
- [ ] 
- [ ] 

## 7. 추가 조사 항목
- [ ] 
- [ ] 

## 8. 참고 출처
- Web Search를 사용한 경우 출처를 적어라.
- Web Search를 사용하지 않은 경우 '내부 Alert DB 기반 분석'이라고 적어라.

공격 유형이 DB에서 탐지되지 않은 경우:
- 사용자가 보고서를 요청하지 않았다면 일반 설명 형식으로 답변해라.
- 사용자가 보고서를 요청했다면 아래 템플릿을 사용해라.

# 공격 유형 분석 보고서

## 1. 탐지 여부
- 요청한 공격 유형:
- 내부 Alert DB 탐지 여부: 탐지되지 않음

## 2. 공격 개념
-

## 3. 일반적인 공격 방식
-

## 4. 주요 피해
-

## 5. 대응 방안
- [ ] 
- [ ] 
- [ ] 

## 6. 참고 출처
-

공통 주의사항:
- 보고서 작성 요청이 아닐 때는 Notion 보고서 템플릿을 사용하지 마라.
- 보고서 작성 요청일 때만 제목, 표, 체크박스를 포함한 Markdown 보고서를 작성해라.
- Alert 상세 내역 표에는 실제 조회된 Alert만 작성해라.
- DB에 존재하지 않는 Alert, IP, 포트, confidence 값을 만들어내지 마라.
"""

    # 대화 기록 + 마지막 DB 조회 결과 + 현재 질문을 하나의 input으로 구성한다.
    model_input = build_model_input(
        user_message=user_message,
        previous_context=previous_context,
        conversation_context=conversation_context
    )

    # 1차 호출
    # 이 단계에서 모델은 답변을 바로 만들 수도 있고, function_call을 요청할 수도 있다.
    response = client.responses.create(
        model=MODEL,
        instructions=instructions,
        tools=tools,
        input=model_input
    )

    # 기본적으로는 이전 context를 유지한다.
    # 새로운 function_call이 발생하면 아래 loop에서 최신 결과로 갱신된다.
    latest_tool_context = previous_context

    # function_call이 여러 번 발생할 수 있으므로 반복 처리한다.
    # 무한 루프 방지를 위해 최대 5회로 제한한다.
    for _ in range(5):
        function_outputs = []

        # 모델 응답 중 function_call 항목만 찾아서 실행한다.
        for item in response.output:
            if item.type == "function_call":
                arguments = json.loads(item.arguments or "{}")

                # 실제 Python 함수 실행
                result = run_local_tool(item.name, arguments)

                # 다음 사용자 질문에서 재사용할 수 있도록 마지막 tool 결과를 저장한다.
                latest_tool_context = {
                    "tool_name": item.name,
                    "arguments": arguments,
                    "result": result
                }

                # 모델에게 돌려줄 function_call_output 생성
                function_outputs.append({
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": json.dumps(result, ensure_ascii=False)
                })

        # 더 이상 실행할 함수가 없으면 최종 답변이 생성된 것으로 보고 종료한다.
        if not function_outputs:
            break

        # 함수 실행 결과를 모델에게 다시 전달한다.
        # previous_response_id를 사용해 방금 전 응답의 흐름을 이어간다.
        response = client.responses.create(
            model=MODEL,
            instructions=instructions,
            tools=tools,
            previous_response_id=response.id,
            input=function_outputs
        )

    return response.output_text, latest_tool_context


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

# Streamlit은 입력할 때마다 스크립트를 다시 실행한다.
# 따라서 session_state에 대화 기록을 저장해야 이전 메시지가 유지된다.
if "messages" not in st.session_state:
    st.session_state.messages = []

# 마지막 Function Calling 결과를 저장하는 공간
# 사용자가 '그걸', '방금 것'이라고 물었을 때 기준 데이터로 사용된다.
if "last_tool_context" not in st.session_state:
    st.session_state.last_tool_context = None

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
    # 현재 입력 이전의 최근 대화 기록만 잘라서 모델에게 전달한다.
    # 너무 오래된 대화까지 넣으면 비용과 컨텍스트가 커지므로 최근 6개만 사용한다.
    conversation_context = st.session_state.messages[-6:]

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
                # previous_context에는 마지막 DB 조회 결과를 전달한다.
                # conversation_context에는 최근 대화 흐름을 전달한다.
                answer, latest_context = generate_report(
                    user_message=user_input,
                    previous_context=st.session_state.last_tool_context,
                    conversation_context=conversation_context
                )

                st.write(answer)

                # 새로 실행된 function_call 결과가 있으면 다음 질문을 위해 저장한다.
                if latest_context:
                    st.session_state.last_tool_context = latest_context

            except Exception as e:
                # API 오류, DB 오류, tool 호출 오류 등이 발생하면 화면에 표시한다.
                answer = f"보고서 생성 중 오류가 발생했습니다: {e}"
                st.error(answer)

    # Assistant 응답도 세션 기록에 저장한다.
    st.session_state.messages.append({
        "role": "assistant",
        "content": answer
    })