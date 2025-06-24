from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import os
import requests
import hashlib
import time
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid
import shutil
from pathlib import Path
import mimetypes

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'antivirus_db')

client = MongoClient(MONGO_URL)
db = client[DB_NAME]

# Collections
scans_collection = db.scans
quarantine_collection = db.quarantine
settings_collection = db.settings

# VirusTotal configuration
VIRUSTOTAL_API_KEY = "0be4edf151c764594b2403b891e1338f1914c1ac282e28202776fff4ffc8a4a9"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2"

# Quarantine directory
QUARANTINE_DIR = "/app/quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Pydantic models
class ScanRequest(BaseModel):
    directory_path: str
    scan_type: str = "quick"  # quick, full, custom

class ScanResult(BaseModel):
    scan_id: str
    file_path: str
    file_name: str
    file_size: int
    file_hash: str
    scan_status: str  # scanning, clean, infected, error
    threat_level: str  # low, medium, high, critical
    virus_names: List[str]
    detection_count: int
    total_engines: int
    scan_date: datetime
    virustotal_data: Optional[Dict[Any, Any]]

class QuarantineItem(BaseModel):
    quarantine_id: str
    original_path: str
    quarantine_path: str
    file_name: str
    threat_level: str
    virus_names: List[str]
    quarantined_date: datetime
    restored: bool = False

# Utility functions
def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of a file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return ""

def scan_file_with_virustotal(file_path: str) -> Dict[str, Any]:
    """Scan file with VirusTotal API"""
    try:
        # First, upload the file
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            params = {'apikey': VIRUSTOTAL_API_KEY}
            
            response = requests.post(
                f"{VIRUSTOTAL_BASE_URL}/file/scan",
                files=files,
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                return {"error": f"Upload failed: {response.status_code}"}
            
            upload_result = response.json()
            resource = upload_result.get('resource')
            
            if not resource:
                return {"error": "No resource ID received"}
            
            # Wait a bit for scanning to start
            time.sleep(2)
            
            # Get scan report
            params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
            response = requests.get(
                f"{VIRUSTOTAL_BASE_URL}/file/report",
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                return {"error": f"Report fetch failed: {response.status_code}"}
            
            return response.json()
            
    except Exception as e:
        return {"error": f"VirusTotal scan failed: {str(e)}"}

def analyze_virustotal_result(vt_result: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze VirusTotal result and determine threat level"""
    if "error" in vt_result:
        return {
            "status": "error",
            "threat_level": "unknown",
            "virus_names": [],
            "detection_count": 0,
            "total_engines": 0
        }
    
    response_code = vt_result.get('response_code', 0)
    if response_code == -2:
        return {
            "status": "scanning",
            "threat_level": "unknown",
            "virus_names": [],
            "detection_count": 0,
            "total_engines": 0
        }
    
    if response_code != 1:
        return {
            "status": "error",
            "threat_level": "unknown",
            "virus_names": [],
            "detection_count": 0,
            "total_engines": 0
        }
    
    positives = vt_result.get('positives', 0)
    total = vt_result.get('total', 0)
    scans = vt_result.get('scans', {})
    
    # Extract virus names
    virus_names = []
    for engine, result in scans.items():
        if result.get('detected'):
            virus_name = result.get('result', 'Unknown threat')
            if virus_name and virus_name not in virus_names:
                virus_names.append(virus_name)
    
    # Determine threat level
    if positives == 0:
        threat_level = "clean"
        status = "clean"
    elif positives <= 2:
        threat_level = "low"
        status = "infected"
    elif positives <= 5:
        threat_level = "medium"
        status = "infected"
    elif positives <= 10:
        threat_level = "high"
        status = "infected"
    else:
        threat_level = "critical"
        status = "infected"
    
    return {
        "status": status,
        "threat_level": threat_level,
        "virus_names": virus_names,
        "detection_count": positives,
        "total_engines": total
    }

def quarantine_file(file_path: str, scan_result: Dict[str, Any]) -> str:
    """Move infected file to quarantine"""
    try:
        quarantine_id = str(uuid.uuid4())
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{quarantine_id}_{file_name}")
        
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        
        # Record in database
        quarantine_item = {
            "quarantine_id": quarantine_id,
            "original_path": file_path,
            "quarantine_path": quarantine_path,
            "file_name": file_name,
            "threat_level": scan_result.get("threat_level", "unknown"),
            "virus_names": scan_result.get("virus_names", []),
            "quarantined_date": datetime.utcnow(),
            "restored": False
        }
        
        quarantine_collection.insert_one(quarantine_item)
        return quarantine_id
        
    except Exception as e:
        print(f"Error quarantining file {file_path}: {e}")
        return ""

def scan_directory(directory_path: str, scan_id: str):
    """Scan all files in a directory"""
    try:
        if not os.path.exists(directory_path):
            return
        
        supported_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.pif', '.com',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.js', '.py', '.php', '.pl', '.sh',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp'
        }
        
        scanned_files = 0
        infected_files = 0
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = Path(file_path).suffix.lower()
                
                # Check if file type is supported
                if file_ext not in supported_extensions:
                    continue
                
                try:
                    # Calculate file info
                    file_size = os.path.getsize(file_path)
                    file_hash = calculate_file_hash(file_path)
                    
                    # Skip very large files (>100MB)
                    if file_size > 100 * 1024 * 1024:
                        continue
                    
                    # Scan with VirusTotal
                    vt_result = scan_file_with_virustotal(file_path)
                    analysis = analyze_virustotal_result(vt_result)
                    
                    # Create scan result
                    scan_result = {
                        "scan_id": scan_id,
                        "file_path": file_path,
                        "file_name": file,
                        "file_size": file_size,
                        "file_hash": file_hash,
                        "scan_status": analysis["status"],
                        "threat_level": analysis["threat_level"],
                        "virus_names": analysis["virus_names"],
                        "detection_count": analysis["detection_count"],
                        "total_engines": analysis["total_engines"],
                        "scan_date": datetime.utcnow(),
                        "virustotal_data": vt_result if "error" not in vt_result else None
                    }
                    
                    # Save to database
                    scans_collection.insert_one(scan_result)
                    scanned_files += 1
                    
                    # Quarantine if infected
                    if analysis["status"] == "infected" and analysis["threat_level"] in ["high", "critical"]:
                        quarantine_id = quarantine_file(file_path, analysis)
                        if quarantine_id:
                            infected_files += 1
                    
                    # Rate limiting for VirusTotal API
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
                    continue
        
        # Update scan summary
        scans_collection.update_many(
            {"scan_id": scan_id},
            {"$set": {
                "total_files_scanned": scanned_files,
                "total_infected_files": infected_files,
                "scan_completed": True,
                "scan_completed_date": datetime.utcnow()
            }}
        )
        
    except Exception as e:
        print(f"Error scanning directory {directory_path}: {e}")

# API Routes
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "antivirus-scanner"}

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a directory scan"""
    try:
        if not os.path.exists(request.directory_path):
            raise HTTPException(status_code=400, detail="Directory does not exist")
        
        scan_id = str(uuid.uuid4())
        
        # Start background scan
        background_tasks.add_task(scan_directory, request.directory_path, scan_id)
        
        # Create initial scan record
        scan_record = {
            "scan_id": scan_id,
            "directory_path": request.directory_path,
            "scan_type": request.scan_type,
            "scan_status": "in_progress",
            "started_date": datetime.utcnow(),
            "total_files_scanned": 0,
            "total_infected_files": 0,
            "scan_completed": False
        }
        
        scans_collection.insert_one(scan_record)
        
        return {"scan_id": scan_id, "status": "started", "message": "Scan started successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and progress"""
    try:
        # Get scan summary
        scan_record = scans_collection.find_one({"scan_id": scan_id}, sort=[("started_date", -1)])
        if not scan_record:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get file results count
        total_results = scans_collection.count_documents({"scan_id": scan_id, "file_path": {"$exists": True}})
        infected_count = scans_collection.count_documents({"scan_id": scan_id, "scan_status": "infected"})
        clean_count = scans_collection.count_documents({"scan_id": scan_id, "scan_status": "clean"})
        
        return {
            "scan_id": scan_id,
            "status": "completed" if scan_record.get("scan_completed", False) else "in_progress",
            "directory_path": scan_record.get("directory_path"),
            "started_date": scan_record.get("started_date"),
            "completed_date": scan_record.get("scan_completed_date"),
            "total_files": total_results,
            "infected_files": infected_count,
            "clean_files": clean_count,
            "scan_progress": "100%" if scan_record.get("scan_completed", False) else "In Progress..."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")

@app.get("/api/scan/results/{scan_id}")
async def get_scan_results(scan_id: str, skip: int = 0, limit: int = 50):
    """Get detailed scan results"""
    try:
        results = list(scans_collection.find(
            {"scan_id": scan_id, "file_path": {"$exists": True}},
            {"_id": 0, "virustotal_data": 0}
        ).skip(skip).limit(limit).sort("scan_date", -1))
        
        return {"scan_id": scan_id, "results": results, "count": len(results)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")

@app.get("/api/scans/history")
async def get_scan_history(limit: int = 20):
    """Get scan history"""
    try:
        # Get unique scans (group by scan_id)
        pipeline = [
            {"$match": {"scan_id": {"$exists": True}}},
            {"$group": {
                "_id": "$scan_id",
                "scan_id": {"$first": "$scan_id"},
                "directory_path": {"$first": "$directory_path"},
                "scan_type": {"$first": "$scan_type"},
                "started_date": {"$first": "$started_date"},
                "completed_date": {"$first": "$scan_completed_date"},
                "scan_completed": {"$first": "$scan_completed"},
                "total_files": {"$sum": {"$cond": [{"$ne": ["$file_path", None]}, 1, 0]}},
                "infected_files": {"$sum": {"$cond": [{"$eq": ["$scan_status", "infected"]}, 1, 0]}}
            }},
            {"$sort": {"started_date": -1}},
            {"$limit": limit}
        ]
        
        history = list(scans_collection.aggregate(pipeline))
        return {"scans": history}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan history: {str(e)}")

@app.get("/api/quarantine")
async def get_quarantine_items():
    """Get quarantined files"""
    try:
        items = list(quarantine_collection.find({}, {"_id": 0}).sort("quarantined_date", -1))
        return {"quarantine_items": items}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get quarantine items: {str(e)}")

@app.post("/api/quarantine/restore/{quarantine_id}")
async def restore_quarantine_item(quarantine_id: str):
    """Restore file from quarantine"""
    try:
        item = quarantine_collection.find_one({"quarantine_id": quarantine_id})
        if not item:
            raise HTTPException(status_code=404, detail="Quarantine item not found")
        
        if item.get("restored", False):
            raise HTTPException(status_code=400, detail="File already restored")
        
        # Restore file
        if os.path.exists(item["quarantine_path"]):
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(item["original_path"]), exist_ok=True)
            shutil.move(item["quarantine_path"], item["original_path"])
            
            # Update database
            quarantine_collection.update_one(
                {"quarantine_id": quarantine_id},
                {"$set": {"restored": True, "restored_date": datetime.utcnow()}}
            )
            
            return {"message": "File restored successfully"}
        else:
            raise HTTPException(status_code=404, detail="Quarantined file not found")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restore file: {str(e)}")

@app.delete("/api/quarantine/delete/{quarantine_id}")
async def delete_quarantine_item(quarantine_id: str):
    """Permanently delete quarantined file"""
    try:
        item = quarantine_collection.find_one({"quarantine_id": quarantine_id})
        if not item:
            raise HTTPException(status_code=404, detail="Quarantine item not found")
        
        # Delete file
        if os.path.exists(item["quarantine_path"]):
            os.remove(item["quarantine_path"])
        
        # Remove from database
        quarantine_collection.delete_one({"quarantine_id": quarantine_id})
        
        return {"message": "File deleted permanently"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get recent scan stats
        total_scans = scans_collection.count_documents({"scan_id": {"$exists": True}})
        total_files_scanned = scans_collection.count_documents({"file_path": {"$exists": True}})
        total_threats_found = scans_collection.count_documents({"scan_status": "infected"})
        quarantine_count = quarantine_collection.count_documents({"restored": False})
        
        # Get recent activity
        recent_scans = list(scans_collection.find(
            {"scan_id": {"$exists": True}},
            {"_id": 0, "scan_id": 1, "directory_path": 1, "started_date": 1, "scan_completed": 1}
        ).sort("started_date", -1).limit(5))
        
        return {
            "total_scans": total_scans,
            "total_files_scanned": total_files_scanned,
            "total_threats_found": total_threats_found,
            "quarantine_count": quarantine_count,
            "recent_scans": recent_scans,
            "last_updated": datetime.utcnow()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard stats: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)