from flask import Flask, request, render_template, render_template_string, abort
import os

app = Flask(__name__)

FLAG_PATH = '/flag' if os.path.exists('/flag') else os.path.join(os.path.dirname(__file__), 'FLAG')

@app.route('/')
def index():
    q = request.args.get('q', '')

    try:
        # Render user input directly without adding extra braces, allowing full SSTI expressions
        rendered_user = render_template_string(q)
    except Exception as e:
        rendered_user = f'<pre class="error">Template error: {str(e)}</pre>'

    return render_template('index.html', rendered=rendered_user, default=q)

@app.route('/flag')
def flag():
    abort(404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)

