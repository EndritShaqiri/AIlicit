"""Entry point: ``python -m alicit listener`` runs the OAuth capture listener."""
import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "listener":
        from .listener import app
        app.run(host="0.0.0.0", port=8080, debug=False)
    else:
        print(__doc__)
