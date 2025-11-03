from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import tempfile
import shutil
from typing import Dict, Any, Optional
import uvicorn
import sys
import logging
from contextlib import asynccontextmanager

sys.path.insert(0, str(Path(__file__).parent.parent))

import proteus
from python.analyzer import ProteusAnalyzer
from python.ml_detector import ProteusMLDetector
from python.yara_engine import ProteusYaraEngine

logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

analyzer = ProteusAnalyzer()
ml_detector = ProteusMLDetector()
yara_engine = ProteusYaraEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n╔═══════════════════════════════════════╗")
    print("║   PROTEUS Web Dashboard Server        ║")
    print("║   FastAPI Backend v0.2.0              ║")
    print("╚═══════════════════════════════════════╝\n")

    try:
        ml_detector.load_model()
        print("[+] ML detector loaded")
    except Exception as e:
        print(f"[!] ML detector failed: {e}")

    try:
        if yara_engine.load_rules():
            print("[+] YARA engine loaded")
        else:
            print("[!] YARA rules not found")
    except Exception as e:
        print(f"[!] YARA engine failed: {e}")

    print(f"\n[*] Server running on http://localhost:8000")
    print(f"[*] Dashboard: http://localhost:8000\n")

    yield


app = FastAPI(title="PROTEUS API", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="web"), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    with open("web/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "ml_loaded": ml_detector.rf_model is not None,
        "yara_loaded": yara_engine.compiled_rules is not None,
    }


@app.get("/api/stats")
async def get_stats():
    """Get system statistics including YARA rule count"""
    stats = {
        "ml_loaded": ml_detector.rf_model is not None,
        "yara_loaded": yara_engine.compiled_rules is not None,
        "yara_info": None
    }

    if yara_engine.compiled_rules:
        try:
            stats["yara_info"] = yara_engine.get_rule_info()
        except Exception as e:
            print(f"[!] Error getting YARA info: {e}")
            stats["yara_info"] = {"rule_files": 0, "error": str(e)}

    return stats


@app.post("/api/scan")
async def scan_file(
    file: UploadFile = File(...),
    ml: str = Form("false"),
    yara: str = Form("false"),
    strings: str = Form("false"),
) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    use_ml = ml.lower() == "true"
    use_yara = yara.lower() == "true"
    use_strings = strings.lower() == "true"
    
    # Accept all file types for analysis
    suffix = Path(file.filename).suffix if Path(file.filename).suffix else ".bin"

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix
    ) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        heuristic_result = analyzer.analyze_single(tmp_path)

        result = {
            "filename": file.filename,
            "size": Path(tmp_path).stat().st_size,
            "heuristic": heuristic_result,
        }

        if use_ml and ml_detector.rf_model:
            try:
                result["ml"] = ml_detector.predict(tmp_path)
            except Exception as e:
                print(f"[!] ML prediction error: {e}")
                result["ml"] = {"error": str(e)}

        if use_yara and yara_engine.compiled_rules:
            try:
                result["yara"] = yara_engine.scan_file(tmp_path)
            except Exception as e:
                print(f"[!] YARA scan error: {e}")
                result["yara"] = {"error": str(e)}

        if use_strings:
            try:
                strings_data = proteus.extract_strings_from_file(tmp_path)
                result["strings"] = {
                    "total_strings": strings_data.total_strings,
                    "encoded_strings": strings_data.encoded_strings,
                    "urls": strings_data.urls[:10],
                    "ips": strings_data.ips[:10],
                    "suspicious_strings": strings_data.suspicious_strings[:20],
                    "registry_keys": strings_data.registry_keys[:10],
                }
            except Exception as e:
                print(f"[!] String extraction error: {e}")
                result["strings"] = {"error": str(e)}

        return result

    except Exception as e:
        print(f"[!] Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            Path(tmp_path).unlink()
        except:
            pass


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="error")