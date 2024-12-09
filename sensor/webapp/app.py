from flask import Flask, render_template, request, Response
import subprocess

app = Flask(__name__)
process = None  # Shared subprocess reference

def stream_process_output(process):
    """Generator that streams process stdout line-by-line."""
    for line in iter(process.stdout.readline, ''):
        yield f"data: {line.strip()}\n\n"
    process.stdout.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_binary', methods=['POST'])
def run_binary():
    """Run the binary specified by the user."""
    global process

    if process and process.poll() is None:
        return "Binary already running", 400

    # Get binary path and arguments from the form
    binary = request.form.get('binary')
    arguments = request.form.get('arguments', '').split()

    if not binary:
        return "Binary path is required", 400

    try:
        # Start the binary
        process = subprocess.Popen(
            [binary, *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return "Binary started successfully", 200
    except Exception as e:
        return f"Error running binary: {str(e)}", 500

@app.route('/run_binary', methods=['GET'])
def stream_output():
    """Stream the output of the running binary."""
    global process
    if process and process.poll() is None:
        return Response(stream_process_output(process), content_type='text/event-stream')
    return "No running binary", 400

@app.route('/send_input', methods=['POST'])
def send_input():
    """Send input to the binary."""
    global process
    if process and process.poll() is None:
        # Send a newline (Enter key) to stdin
        process.stdin.write("\n")
        process.stdin.flush()
        return "Input sent", 200
    return "No running binary", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
