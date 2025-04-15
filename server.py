# Import the Flask class and the render_template function
from flask import Flask, render_template

# Create an instance of the Flask class.
app = Flask(__name__) # Flask will look for templates in a 'templates' folder

# Define a route for the application's root URL ("/").
@app.route("/")
def index():
  """
  This function is the view function for the "/" route.
  It now renders an HTML template file instead of returning a string.
  Flask looks for this file in a folder named 'templates'
  in the same directory as this script.
  """
  # Render the index.html template
  # You can pass variables to the template like:
  # return render_template('index.html', title='My Landing Page')
  return render_template('index.html')

# This conditional block allows the script to be run directly using `python server.py`.
if __name__ == "__main__":
  # Run the Flask development server
  # debug=True enables auto-reloading and error pages (disable in production)
  # host='0.0.0.0' makes it accessible on your network
  app.run(debug=True, host='0.0.0.0', port=5000)
