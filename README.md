### CodeGuard

C/C++ 소스 트리를 대상으로 위험 패턴을 빠르게 점검할 수 있는 도구입니다.
실행 후 프로젝트 루트 경로를 입력하면 하위 전체 파일을 재귀적으로 검사하고, 파일/라인/컬럼 단위로 결과를 출력합니다.

#### Features

* 프로젝트 루트 경로 입력만으로 전체 소스 재귀 스캔
* 파일:라인:컬럼 형태의 출력 + 해당 라인 프리뷰

#### Rules (MVP)

* **CG0001**: 금지 함수 호출 탐지
  `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `system`, `popen`
* **CG0002**: `scanf` 포맷에서 폭 지정 없는 `%s` 사용 탐지
  예: `scanf("%s", buf)`

#### Build

* Visual Studio 2022로 `CodeGuardCLI.sln` 열기
* `x64` / `Debug` 또는 `Release` 빌드

#### Usage

1. 실행: `bin\<Config>\CodeGuardCLI.exe`
2. 프롬프트 `>` 에 프로젝트 루트 경로 입력
   예: `C:\Users\OF\source\repos\MMM`

#### Exit Codes

* `0`: 발견 없음
* `1`: 발견 있음
* `2`: 입력 경로 오류

#### Notes

* 현재 버전은 **정확도가 높은 규칙부터** MVP로 구성했습니다.
  (추후 타입/AST 기반 규칙, SARIF 출력, CI 연동 등으로 확장 가능)

---

## 저장소 설명(About / Short description)

* **KOR:** VS2022 콘솔 기반 C/C++ 보안 CLI
* **ENG:** Lightweight C/C++ security linter CLI for VS2022

---

## 릴리즈 설명(Release 텍스트 예시)

**v0.1.0 (MVP)**

* CG0001 금지 함수 호출 탐지
* CG0002 scanf `%s` 폭 미지정 탐지
* 파일/라인/컬럼 + 라인 프리뷰 출력
* VS2022 x64 Debug/Release 지원
