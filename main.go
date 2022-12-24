package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

const saltLength = 32

func main() {
    
	
    http.HandleFunc("/", handleRoot)
    http.ListenAndServe(":8080", nil)
}

// Match represents a football match
type Match struct {
	Date      string `json:"Date"`
	HomeTeam  string `json:"HomeTeam"`
	AwayTeam  string `json:"AwayTeam"`
	BTTS      string `json:"BTTS"`
	OverUnder string `json:"OverUnder"`
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Render the login form
		tmpl, err := template.New("templateName").Parse(`
<html>
<head>
  <title>Login</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f2f2f2;
    }
    .container {
      width: 500px;
      margin: 50px auto;
      background-color: white;
      border-radius: 5px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      padding: 30px;
    }
    h1 {
      text-align: center;
      margin-bottom: 30px;
      color: #333;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 12px 20px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    input[type="submit"] {
      width: 100%;
      background-color: #4CAF50;
      color: white;
      padding: 14px 20px;
      margin: 8px 0;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    input[type="submit"]:hover {
      background-color: #45a049;
    }
    p.error {
      color: red;
      text-align: center;
      margin-bottom: 30px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    {{if .}}
    <p class="error">{{.}}</p>
    {{end}}
    <form action="/" method="post">
      <label for="username">Username:</label><br>
      <input type="text" id="username" name="username"><br>
      <label for="password">Password:</label><br>
      <input type="password" id="password" name="password"><br><br>
      <input type="submit" value="Submit">
	  </form>
  </div>
</body>
</html>
`)
   
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		// Check the username and password
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Open a connection to the database
		db, err := sql.Open("sqlite3", "file:mydb.db")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Retrieve the salt and hashed password for the entered username
		var salt string
		var hash string
		err = db.QueryRow("SELECT salt, hash FROM users WHERE username=?", username).Scan(&salt, &hash)
		if err == sql.ErrNoRows {
			// If the username is not found, render the login form with an error message
			tmpl2, err := template.New("templatename").Parse(`
<html>
<head>
  <title>Login</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f2f2f2;
    }
    .container {
      width: 500px;
      margin: 50px auto;
      background-color: white;
      border-radius: 5px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      padding: 30px;
    }
    h1 {
      text-align: center;
      margin-bottom: 30px;
      color: #333;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 12px 20px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    input[type="submit"] {
      width: 100%;
      background-color: #4CAF50;
      color: white;
      padding: 14px 20px;
      margin: 8px 0;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    input[type="submit"]:hover {
      background-color: #45a049;
    }
    p.error {
      color: red;
      text-align: center;
      margin-bottom: 30px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    {{if .}}
    <p class="error">{{.}}</p>
    {{end}}
    <form action="/" method="post">
      <label for="username">Username:</label><br>
      <input type="text" id="username" name="username"><br>
      <label for="password">Password:</label><br>
      <input type="password" id="password" name="password"><br><br>
      <input type="submit" value="Submit">
	  </form>
  </div>
</body>
</html>
`)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tmpl2.Execute(w, "Invalid username or password. Please try again.")
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Decode the salt and hash from hexadecimal
		saltBytes, err := hex.DecodeString(salt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Hash the entered password with the salt using SHA-256
		passwordHash := sha256.Sum256(append([]byte(password), saltBytes...))

		// Compare the resulting hash with the stored hash
		if constantTimeCompare(passwordHash[:], hashBytes) {
			// If the password is correct, read the JSON file
			data, err := ioutil.ReadFile("prediction.json")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Unmarshal the JSON file into a slice of Match structs
			var matches []Match
			err = json.Unmarshal(data, &matches)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Parse the HTML template
			tmpl3,err := template.New("resultTemplate").Parse(`<html>
  <head>
    <title>Matches</title>
    <style>
      table {
        width: 100%;
        border-collapse: collapse;
      }

      th,
      td {
        text-align: left;
        padding: 8px;
      }

      tr:nth-child(even) {
        background-color: #f2f2f2;
      }

      th {
        background-color: #4caf50;
        color: white;
      }
    </style>
  </head>
  <body>
    <table>
      <tr>
        <th>Date</th>
        <th>Home Team</th>
        <th>Away Team</th>
        <th>BTTS</th>
        <th>Over/Under</th>
      </tr>
      {{ range . }}
      <tr>
        <td>{{ .Date }}</td>
        <td>{{ .HomeTeam }}</td>
        <td>{{ .AwayTeam }}</td>
        <td>{{ .BTTS }}</td>
        <td>{{ .OverUnder }}</td>
      </tr>
      {{ end }}
    </table>
  </body>
</html>`)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Execute the template with the data
			err = tmpl3.Execute(w, matches)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// If the password is incorrect, render the login form with an error message
			tmpl4,err := template.New("templateName").Parse(`
<html>
<head>
  <title>Login</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f2f2f2;
    }
    .container {
      width: 500px;
      margin: 50px auto;
      background-color: white;
      border-radius: 5px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      padding: 30px;
    }
    h1 {
      text-align: center;
      margin-bottom: 30px;
      color: #333;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 12px 20px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    input[type="submit"] {
      width: 100%;
      background-color: #4CAF50;
      color: white;
      padding: 14px 20px;
      margin: 8px 0;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    input[type="submit"]:hover {
      background-color: #45a049;
    }
    p.error {
      color: red;
      text-align: center;
      margin-bottom: 30px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    {{if .}}
    <p class="error">{{.}}</p>
    {{end}}
    <form action="/" method="post">
      <label for="username">Username:</label><br>
      <input type="text" id="username" name="username"><br>
      <label for="password">Password:</label><br>
      <input type="password" id="password" name="password"><br><br>
      <input type="submit" value="Submit">
	  </form>
  </div>
</body>
</html>
`)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tmpl4.Execute(w, "Invalid username or password. Please try again.")
		}
	}
}
