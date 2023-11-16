import uvicorn

if '__main__' == __name__:
    uvicorn.run("lambda_function:app", host='0.0.0.0', port=8001)