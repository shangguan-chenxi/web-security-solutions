<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    </style>
</head>
<body>
    
<?php
/*
 Anti-CSRF && SQL-Injection-proof form
*/

session_start();
$TOKEN_SOURCE = "Test12345qazXSWedcVFR".mt_rand()."--Admin++Manage**CSRF||"; // source string of csrf token
$TIME_LIMIT = 1 * 60; //Pre-defined lifespan of the CSRF token (in seconds)

/*
Generate a token via given string and date()
record the time stamp when token is generated
A SHA-256 encrypted string is returned

Para:
    $source: a string for generating a CSRF token
*/
function generate_csrf_token($source){
    $token = hash("sha256", $source.date("Y:m:d:h:i:s"));
    $_SESSION["csrf_token"] = $token;
    $_SESSION["token_time"] = time();
    return $token;
}

/*
Compare the server-stored and client-submitted CSRF token
&&
Check if the token is timeout
It returns a boolean (true/false)

Para:
    $submitted_token: CSRF token attached to the form
    $time_limit: Pre-defined lifespan of the CSRF token (in seconds)
*/
function check_csrf_token($submitted_token, $time_limit){
    return (strcmp($_SESSION["csrf_token"], $submitted_token) == 0 && time() - $_SESSION["token_time"] < $time_limit);
}

$HOST = "";
$USER = "";
$PASSWORD = "";
$DB = "";

$MYSQLI = new mysqli($HOST, $USER, $PASSWORD, $DB);
if (mysqli_connect_error()){printf("MySQL Database Connection Error: %s\n", mysqli_connect_error()); exit();}

/*
Parametric Query for credentials validation
A boolean is returned (true/false)

Para:
    $id: Credential entered by user
    $password: Refer above
*/
function login_check($id, $password){
	global $MYSQLI;
	$allow_login = false;
	$query = "SELECT * FROM `admin` WHERE `username` = ? AND `password` = ?"; // Change it when necessary
	$cmd = $MYSQLI->prepare($query);
	$cmd->bind_param("ss", $id, $password); // Change it when necessary
	$cmd->execute();
	$result = $cmd->get_result();
	$row = mysqli_fetch_assoc($result);
	if (strcmp($row['username'],$id) == 0 && strcmp($row['password'],$password) == 0) { // Change it when necessary
		$allow_login = true;
	}
	mysqli_free_result($result);
	return $allow_login;
}


/* Precess the data after user submitted */
if (isset($_POST['login'])){
	$id = $_POST['id'];
	$pwd = $_POST['pwd'];
	$csrf_token = $_POST['csrf_token'];
	if (check_csrf_token($csrf_token, $TIME_LIMIT)){
        if (login_check($id,$pwd)){
            // TO DO
        }
        else {
            echo '<script>console.log("Invalid credentials");</script>';
        }
    }
    else {
        echo '<script>console.log("CSRF Token invalid/timeout");</script>';
    }
    unset($_POST['id']);unset($_POST['pwd']);unset($_POST['login']);unset($_POST['csrf_token']);unset($_SESSION["csrf_token"]);unset($_SESSION["token_time"]);
}
?>

<div class="pageHeader">
    </br>
    <h1>Login</h1>
</div>

<form action="" method="post">
<div class="loginInputs">
    <!-- Attach the CSRF token to the form, put it in a hidden text box -->
    <input type="hidden" name="csrf_token" id="csrf_token" value="<?php echo generate_csrf_token($TOKEN_SOURCE);?>"/>
    <p1><strong>User:</strong> <input type="text" name="id" id="loginaInput" placeholder="Username" required/></br> </p1>
    <p2><strong>Pass:</strong> <input type="text" name="pwd" id="loginpInput " placeholder="Password" required/> </br></p2>
    <input name="login" type="submit" value="Submit">
</div>
</form>
</body>
</html>
