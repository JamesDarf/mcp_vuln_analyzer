# Usage: python main.py <target_path>
import os
import argparse
from pathlib import Path
import openai
from typing import List, Dict

SUPPORTED_EXTENSIONS = {'.py', '.js', '.php'}
CHUNK_SIZE = 3000


def collect_code_files(root_path: Path) -> List[Path]:
    code_files = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix in SUPPORTED_EXTENSIONS:
                code_files.append(path)
    return code_files


def split_into_chunks(content: str, chunk_size: int = CHUNK_SIZE) -> List[str]:
    return [content[i:i + chunk_size] for i in range(0, len(content), chunk_size)]


def analyze_chunk_gpt(chunk: str, filename: str) -> List[Dict]:
    prompt = f"""
    아래는 보안 분석을 위한 코드입니다. 보안 취약점이 있다면 해당 유형과 설명을 아래 형식으로 출력하세요:
    [VULN_TYPE] 설명 - 파일 경로:라인 번호

    코드 파일: {filename}
    코드:
    {chunk}
    """

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "당신은 보안 분석 전문가입니다."},
                {"role": "user", "content": prompt}
            ]
        )
        result = response.choices[0].message.content.strip()
        return parse_result(result)
    except Exception as e:
        print(f"[ERROR] GPT 호출 실패: {e}")
        return []


def parse_result(result: str) -> List[Dict]:
    parsed = []
    for line in result.splitlines():
        if line.startswith('['):
            try:
                vuln_type = line.split(']')[0][1:]
                desc_and_loc = line.split('] ')[1]
                desc, loc = desc_and_loc.rsplit(' - ', 1)
                parsed.append({
                    'type': vuln_type,
                    'description': desc,
                    'location': loc
                })
            except Exception as e:
                print(f"[WARN] 파싱 실패: {line} -> {e}")
    return parsed


def main():
    parser = argparse.ArgumentParser(description="MCP 기반 보안 자동 분석 도구")
    parser.add_argument("target", help="분석 대상 zip 또는 디렉토리 경로")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print("[ERROR] 경로가 존재하지 않습니다.")
        return

    # Zip 압축 해제 필요 시 처리 (생략 가능)
    if target_path.suffix == ".zip":
        import zipfile
        extract_dir = target_path.with_suffix("")
        with zipfile.ZipFile(target_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        target_path = extract_dir

    results = []
    for file_path in collect_code_files(target_path):
        with open(file_path, encoding='utf-8', errors='ignore') as f:
            content = f.read()
        chunks = split_into_chunks(content)
        for chunk in chunks:
            analysis = analyze_chunk_gpt(chunk, str(file_path))
            results.extend(analysis)

    print("\n[✅ 분석 결과 요약]")
    for item in results:
        print(f"[{item['type']}] {item['description']} - {item['location']}")


if __name__ == '__main__':
    main()
