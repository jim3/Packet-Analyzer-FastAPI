from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from packets import get_packets


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


class PacketResult(BaseModel):
    ip: str
    mac: str
    udp: str
    tcp: str
    iplocation: str
    dns_query: str
    http_requests: str


@app.post("/packets")
async def analyze_packets(packets: UploadFile = File(...)):
    result = get_packets(packets.filename)
    return JSONResponse(content=result)


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("templates/index.html", "r") as file:
        content = file.read()
    return content


@app.get("/about", response_class=HTMLResponse)
async def about():
    with open("templates/about.html", "r") as file:
        content = file.read()
    return content
