<?php

require '../PHPMailer/Exception.php';
require '../PHPMailer/PHPMailer.php';
require '../PHPMailer/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

	if( isset($_POST["submit"]) )
	{
		$fullname       = $_POST["fullname"];
		$email          = $_POST["email"];
		$telefon		= $_POST["telefon"];
		$username       = $_POST["username"];
		$password       = $_POST["password"];
		$passwordRepeat = $_POST["passwordRepeat"];


		$vkey = md5(time());
		
		require_once '../includes/functions.inc.php';
		require_once '../includes/dbconnect.php';
		
		if( emptyInputSignup($fullname, $email, $username, $password, $passwordRepeat, $telefon) !== false )
		{
			header("location: ../signup.php?error=emptyinput");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( invalidUsername($username) !== false )
		{
			header("location: ../signup.php?error=invalidusername");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( invalidEmail($email) !== false )
		{
			header("location: ../signup.php?error=invalidemail");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( passwordsMatch($password, $passwordRepeat) !== false )
		{
			header("location: ../signup.php?error=passwordmismatch");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( usernameExists($conn, $username) !== false )
		{
			header("location: ../signup.php?error=usernametaken");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( emailExists($conn, $email) !== false )
		{
			header("location: ../signup.php?error=emailregistered");
			header('HTTP/1.1 200 OK');
			exit();
		}
		if( phonelong($telefon) !== false )
		{
			header("location: ../signup.php?error=phonetoolong");
			header('HTTP/1.1 200 OK');
			exit();
		}

		$mail = new PHPMailer();
    $mail->IsSMTP();
    $mail->Mailer = "smtp";
    $mail->SMTPDebug  = 1;
    $mail->SMTPAuth   = TRUE;
    $mail->SMTPSecure = "ssl";
    $mail->Port       = 465;
    $mail->Host       = "webivot.com";
    $mail->Username   = "contact@webivot.com";
    $mail->Password   = "cbogdan2323";

    $mail->IsHTML(true);
	$mail->AddAddress($email, $username);
	$mail->SetFrom("contact@webivot.com", "Webivot");
	$mail->Subject = "Webivot Email Verification";
	$content = "<h4>Your code for email verification is:</h4><h2 style='font-weight: bold;'>$vkey</h2>
		<br><h4><a href='https://webivot.com/verification.php'>CLICK HERE TO VERIFY</a></h4>";
	$mail->isHTML(true);
	$mail->MsgHTML($content);
	if (!$mail->Send()) {
		echo "Error while sending Email.";
		var_dump($mail);
	} else {
		echo "Email sent successfully";
	}

	}
	createUser($conn, $fullname, $email, $username, $password, $telefon, $vkey);
