# YunoHost app generator

This is a Flask app generating a draft .zip of a YunoHost application after filling a form

Official instance: <https://appgenerator.yunohost.org>

## Developement

You can use [PDM](https://pdm-project.org) to install deps and run the app.

```bash
# Generate the virtualenv
pdm install

# Fetch the css and javascript assets (only to be run once or after a git pull)
pdm run fetch_assets
```

And then start the dev server (you can pass arguments that will be passed to Flask):

```bash
pdm run start
```

## Translation

It's based on Flask-Babel : <https://python-babel.github.io/flask-babel/>

You can use PDM to run the commands:

```bash
pdm run update_translations
```

To initialize a new locale (here, fr):
```bash
pdm run translation_create fr
```
