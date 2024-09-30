In powershell, with [fnm](https://github.com/Schniz/fnm) installed:

# Environment
```
fnm env --use-on-cd --shell power-shell | Out-String | Invoke-Expression
```

# Install
```
npm install -g bootprint
npm install -g bootprint-json-schema
```

# Run
```
cd \temp
cp C:\[project_root]\event_tracker\static\eventstream\eventstream.schema.json .
bootprint json-schema eventstream.schema.json .
```

* Open index.html in browser
* Save as webpage
* Paste source over the top of schema-doc.html
* Commit html file _excluding_ the CSS path change