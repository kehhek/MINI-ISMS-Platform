import os
from app import create_app

app = create_app()

SAFE_PORT = 5050

if __name__ == '__main__':
    port = int(os.getenv('PORT', str(SAFE_PORT)))
    print(f"Mini ISMS app starting on: http://127.0.0.1:{port}/login")
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', '0') == '1')