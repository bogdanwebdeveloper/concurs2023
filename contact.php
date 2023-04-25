<?php
error_reporting(E_ERROR | E_PARSE);
date_default_timezone_set('Europe/Berlin');
require_once("captcha/AntiSpam.php");
$q = AntiSpam::getRandomQuestion();
header('Content-type: text/html; charset=utf-8');


#########################################################################
#	Kontaktformular.com         					                                #
#	http://www.kontaktformular.com        						                    #
#	All rights by KnotheMedia.de                                    			#
#-----------------------------------------------------------------------#
#	I-Net: http://www.knothemedia.de                            					#
#########################################################################
// Do NOT remove the copyright notice!


$script_root = substr(
	__FILE__,
	0,
	strrpos(
		__FILE__,
		DIRECTORY_SEPARATOR
	)
) . DIRECTORY_SEPARATOR;

$remote = getenv("REMOTE_ADDR");

function encrypt($string, $key)
{
	$result = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key)) - 1, 1);
		$char = chr(ord($char) + ord($keychar));
		$result .= $char;
	}
	return base64_encode($result);
}

@require('config.php');
require_once("captcha/AntiSpam.php");
include("PHPMailer/Secureimage.php");
// form-data should be deleted
if (isset($_POST['delete']) && $_POST['delete']) {
	unset($_POST);
}

// form has been sent
if (isset($_POST["en-us-kf-km"]) && $_POST["en-us-kf-km"]) {

	// clean data

	$name      	= stripslashes($_POST["name"]);
	$place		= stripslashes($_POST["place"]);
	$telephone		= stripslashes($_POST["telephone"]);
	$email      = stripslashes($_POST["email"]);
	$subject   	= stripslashes($_POST["subject"]);
	$message  = stripslashes($_POST["message"]);
	if ($cfg['DATA_PRIVACY_POLICY']) {
		$data_protection = stripslashes($_POST["data_protection"]);
	}
	if ($cfg['Security_code']) {
		$sicherheits_eingabe = encrypt($_POST["sicherheitscode"], "8h384ls94");
		$sicherheits_eingabe = str_replace("=", "", $sicherheits_eingabe);
	}

	$date = date("d.m.Y | H:i");
	$ip = $_SERVER['REMOTE_ADDR'];
	$UserAgent = $_SERVER["HTTP_USER_AGENT"];
	$host = getHostByAddr($remote);


	// formcheck
	if (!$name) {
		$fehler['name'] = "<span class='errormsg'><strong>Required field</strong></span>";
	}

	if (!preg_match("/^[0-9a-zA-ZÄÜÖ_.-]+@[0-9a-z.-]+\.[a-z]{2,6}$/", $email)) {
		$fehler['email'] = "<span class='errormsg'><strong>Required field</strong></span>";
	}

	if (!$subject) {
		$fehler['subject'] = "<span class='errormsg'><strong>Required field</strong></span>";
	}

	if (!$message) {
		$fehler['message'] = "<span class='errormsg'><strong>Required field</strong></span>";
	}



	// -------------------- SPAMPROTECTION ERROR MESSAGES START ----------------------
	if ($cfg['Security_code'] && $sicherheits_eingabe != $_SESSION['captcha_spam']) {
		unset($_SESSION['captcha_spam']);
		$fehler['captcha'] = "<span class='errormsg'>The <strong>security code</strong> was wrong.</span>";
	}


	if ($cfg["Security_question"]) {
		$answer = AntiSpam::getAnswerById(intval($_POST["q_id"]));
		if (isset($_POST["q"]) && $_POST["q"] != $answer) {
			$fehler['q_id12'] = "<span class='errormsg'>Please answer the <strong>security question</strong> correctly.</span>";
		}
	}



	if ($cfg['Honeypot'] && (!isset($_POST["mail"]) || '' != $_POST["mail"])) {
		$fehler['Honeypot'] = "<span class='errormsg'>Spam suspected. Please check your entries.</span>";
	}

	if ($cfg['Time-out'] && (!isset($_POST["chkspmtm"]) || '' == $_POST["chkspmtm"] || '0' == $_POST["chkspmtm"] || (time() - (int) $_POST["chkspmtm"]) < (int) $cfg['Time-out'])) {
		$fehler['Time-out'] = "<span class='errormsg'>Please wait a few seconds before submitting the form again.</span>";
	}

	if ($cfg['Click_check'] && (!isset($_POST["chkspmkc"]) || 'chkspmhm' != $_POST["chkspmkc"])) {
		$fehler['Click_check'] = "<span class='errormsg'>Click the send button with the mouse to send the form.</span>";
	}

	if ($cfg['Links'] < preg_match_all('#http(s?)\:\/\/#is', $message, $irrelevantMatches)) {
		$fehler['Links'] = "<span class='errormsg'>Your message may " . (0 == $cfg['Links'] ?
			'not contain any links ' : (1 == $cfg['Links'] ?
				'only one link' :
				'a maximum of ' . $cfg['Links'] . ' Links'
			)
		) . ".</span>";
	}

	if ('' != $cfg['Badwordfilter'] && 0 !== $cfg['Badwordfilter'] && '0' != $cfg['Badwordfilter']) {
		$badwords = explode(',', $cfg['Badwordfilter']);			// the configured badwords
		$badwordFields = explode(',', $cfg['Badwordfields']);		// the configured fields to check for badwords
		$badwordMatches = array();									// the badwords that have been found in the fields

		if (0 < count($badwordFields)) {
			foreach ($badwords as $badword) {
				$badword = trim($badword);												// remove whitespaces from badword
				$badwordMatch = str_replace('%', '', $badword);							// take human readable badword for error-message
				$badword = addcslashes($badword, '.:/');								// make ., : and / preg_match-valid
				if ('%' != substr($badword, 0, 1)) {
					$badword = '\\b' . $badword;
				}			// if word mustn't have chars before > add word boundary at the beginning of the word
				if ('%' != substr($badword, -1, 1)) {
					$badword = $badword . '\\b';
				}			// if word mustn't have chars after > add word boundary at the end of the word
				$badword = str_replace('%', '', $badword);								// if word is allowed in the middle > remove all % so it is also allowed in the middle in preg_match 
				foreach ($badwordFields as $badwordField) {
					if (preg_match('#' . $badword . '#is', $_POST[trim($badwordField)]) && !in_array($badwordMatch, $badwordMatches)) {
						$badwordMatches[] = $badwordMatch;
					}
				}
			}

			if (0 < count($badwordMatches)) {
				$fehler['Badwordfilter'] = "<span class='errormsg'>The following expressions are not allowed: " . implode(', ', $badwordMatches) . "</span>";
			}
		}
	}
	// -------------------- SPAMPROTECTION ERROR MESSAGES END ----------------------


	if ($cfg['DATA_PRIVACY_POLICY'] && isset($data_protection) && $data_protection == "") {
		$fehler['data_protection'] = "<span class='errormsg'>You must accept the <strong>data privacy policy</strong>.</span>";
	}

	// there are NO errors > upload-check
	if (!isset($fehler) || count($fehler) == 0) {
		$error             = false;
		$errorMessage      = '';
		$uploadErrors      = array();
		$uploadedFiles     = array();
		$totalUploadSize   = 0;
		$j = 0;


		if (2 == $cfg['UPLOAD_ACTIVE'] && in_array($_SERVER['REMOTE_ADDR'], $cfg['BLACKLIST_IP']) === true) {
			$error = true;
			$uploadErrors[$j]['name'] = '';
			$uploadErrors[$j]['error'] = "You are not allowed to upload files.";
			$j++;
		}



		if (!$error) {
			for ($i = 0; $i < $cfg['NUM_ATTACHMENT_FIELDS']; $i++) {
				if ($_FILES['f']['error'][$i] == UPLOAD_ERR_NO_FILE) {
					continue;
				}

				$extension = explode('.', $_FILES['f']['name'][$i]);
				$extension = strtolower($extension[count($extension) - 1]);
				$totalUploadSize += $_FILES['f']['size'][$i];

				if ($_FILES['f']['error'][$i] != UPLOAD_ERR_OK) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					switch ($_FILES['f']['error'][$i]) {
						case UPLOAD_ERR_INI_SIZE:
							$uploadErrors[$j]['error'] = 'The file is too large (PHP-Ini directive).';
							break;
						case UPLOAD_ERR_FORM_SIZE:
							$uploadErrors[$j]['error'] = 'The file is too large (MAX_FILE_SIZE in HTML form).';
							break;
						case UPLOAD_ERR_PARTIAL:
							if (2 == $cfg['UPLOAD_ACTIVE']) {
								$uploadErrors[$j]['error'] = 'The file was only partially uploaded.';
							} else {
								$uploadErrors[$j]['error'] = 'The file was only partially sent.';
							}
							break;
						case UPLOAD_ERR_NO_TMP_DIR:
							$uploadErrors[$j]['error'] = 'No temporary folder found.';
							break;
						case UPLOAD_ERR_CANT_WRITE:
							$uploadErrors[$j]['error'] = 'Error while saving the file.';
							break;
						case UPLOAD_ERR_EXTENSION:
							$uploadErrors[$j]['error'] = 'Unknown error caused by an extension.';
							break;
						default:
							if (2 == $cfg['UPLOAD_ACTIVE']) {
								$uploadErrors[$j]['error'] = 'Unknown error during upload.';
							} else {
								$uploadErrors[$j]['error'] = 'Unknown error when sending the email attachment.';
							}
					}

					$j++;
					$error = true;
				}
				if ($totalUploadSize > $cfg['MAX_ATTACHMENT_SIZE'] * 1024) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					$uploadErrors[$j]['error'] = 'Maximum upload reached (' . $cfg['MAX_ATTACHMENT_SIZE'] . ' KB).';
					$j++;
					$error = true;
				}
				if ($_FILES['f']['size'][$i] > $cfg['MAX_FILE_SIZE'] * 1024) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					$uploadErrors[$j]['error'] = 'The file is too large (max. ' . $cfg['MAX_FILE_SIZE'] . ' KB).';
					$j++;
					$error = true;
				}
				if (!empty($cfg['WHITELIST_EXT']) && strpos($cfg['WHITELIST_EXT'], $extension) === false) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					$uploadErrors[$j]['error'] = 'The file extension is not allowed.';
					$j++;
					$error = true;
				}
				if (preg_match("=^[\\:*?<>|/]+$=", $_FILES['f']['name'][$i])) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					$uploadErrors[$j]['error'] = 'Invalid characters in the file name (\/:*?<>|).';
					$j++;
					$error = true;
				}
				if (2 == $cfg['UPLOAD_ACTIVE'] && file_exists($cfg['UPLOAD_FOLDER'] . '/' . $_FILES['f']['name'][$i])) {
					$uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
					$uploadErrors[$j]['error'] = 'The file already exists. Please change the file name.';
					$j++;
					$error = true;
				}
				if (!$error) {
					if (2 == $cfg['UPLOAD_ACTIVE']) {
						move_uploaded_file($_FILES['f']['tmp_name'][$i], $cfg['UPLOAD_FOLDER'] . '/' . $_FILES['f']['name'][$i]);
					}
					$uploadedFiles[$_FILES['f']['tmp_name'][$i]] = $_FILES['f']['name'][$i];
				}
			}
		}

		if ($error) {
			$errorMessage = 'The following errors occurred while sending the contact form:' . "\n";
			if (count($uploadErrors) > 0) {
				$tmp = '';
				foreach ($uploadErrors as $err) {
					$tmp .= '<strong>' . $err['name'] . "</strong><br/>\n- " . $err['error'] . "<br/><br/>\n";
				}
				$tmp = "<br/><br/>\n" . $tmp;
			}
			$errorMessage .= $tmp . '';
			$fehler['upload'] = "<span class='errormsg' style='display: block;'>" . $errorMessage . "</span>";
		}
	}


	// there are NO errors > send mail
	if (!isset($fehler)) {
		// ------------------------------------------------------------
		// -------------------- send mail to admin --------------------
		// ------------------------------------------------------------

		// ---- create mail-message for admin
		$mailcontent  = "You've received the following information through the contact form:\n" . "-------------------------------------------------------------------------\n\n";
		$mailcontent .= "Name: " . $name . "\n";
		$mailcontent .= "Email: " . $email . "\n\n";
		$mailcontent .= "Place: " . $place . "\n";
		$mailcontent .= "Telephone: " . $telephone . "\n";
		$mailcontent .= "\nSubject: " . $subject . "\n";
		$mailcontent .= "Message:\n" . $message = preg_replace("/\r\r|\r\n|\n\r|\n\n/", "\n", $message) . "\n\n";
		if (count($uploadedFiles) > 0) {
			if (2 == $cfg['UPLOAD_ACTIVE']) {
				$mailcontent .= "\n\n";
				$mailcontent .= 'The following files have been uploaded:' . "\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - ' . $cfg['DOWNLOAD_URL'] . '/' . $cfg['UPLOAD_FOLDER'] . '/' . $filename . "\n";
				}
			} else {
				$mailcontent .= "\n\n";
				$mailcontent .= 'The following files have been attached:' . "\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - ' . $filename . "\n";
				}
			}
		}
		if ($cfg['DATA_PRIVACY_POLICY']) {
			$mailcontent .= "\n\nData protection: " . $data_protection . " \n";
		}
		$mailcontent .= "\n\nIP address: " . $ip . "\n";
		$mailcontent = strip_tags($mailcontent);

		// ---- get attachments for admin
		$attachments = array();
		if (1 == $cfg['UPLOAD_ACTIVE'] && count($uploadedFiles) > 0) {
			foreach ($uploadedFiles as $tempFilename => $filename) {
				$attachments[$filename] = file_get_contents($tempFilename);
			}
		}

		$success = false;

		// ---- send mail to admin
		if ($smtp['enabled'] !== 0) {
			require_once __DIR__ . '/smtp.php';
			$success = SMTP::send(
				$smtp['host'],
				$smtp['user'],
				$smtp['password'],
				$smtp['encryption'],
				$smtp['port'],
				$email,
				$yourname,
				$recipient,
				$subject,
				$mailcontent,
				(2 == $cfg['UPLOAD_ACTIVE'] ? array() : $uploadedFiles),
				$cfg['UPLOAD_FOLDER'],
				$smtp['debug']
			);
		} else {
			$success = sendMyMail($email, $name, $recipient, $subject, $mailcontent, $attachments);
		}

		// ------------------------------------------------------------
		// ------------------- send mail to customer ------------------
		// ------------------------------------------------------------
		if (
			$success &&
			(2 == $cfg['Send_copy'] || 																// send copy always
				(1 == $cfg['Send_copy'] && isset($_POST['mail-copy']) && 1 == $_POST['mail-copy'])		// send copy only if customer want to
			)
		) {

			// ---- create mail-message for customer
			$mailcontent  = "Many thanks for your email. We will answer as soon as possible.\n\n";
			$mailcontent .= "Summary: \n" .  "-------------------------------------------------------------------------\n\n";
			$mailcontent .= "Name: " . $name . "\n";
			$mailcontent .= "Email: " . $email . "\n\n";
			$mailcontent .= "Place: " . $place . "\n";
			$mailcontent .= "Telephone: " . $telephone . "\n";
			$mailcontent .= "\nSubject: " . $subject . "\n";
			$mailcontent .= "Message:\n" . str_replace("\r", "", $message) . "\n\n";
			if (count($uploadedFiles) > 0) {
				$mailcontent .= 'You have transferred the following files:' . "\n";
				foreach ($uploadedFiles as $file) {
					$mailcontent .= ' - ' . $file . "\n";
				}
			}
			$mailcontent = strip_tags($mailcontent);

			// ---- send mail to customer
			if ($smtp['enabled'] !== 0) {
				SMTP::send(
					$smtp['host'],
					$smtp['user'],
					$smtp['password'],
					$smtp['encryption'],
					$smtp['port'],
					$recipient,
					$yourname,
					$email,
					"Your request",
					$mailcontent,
					array(),
					$cfg['UPLOAD_FOLDER'],
					$smtp['debug']
				);
			} else {
				$success = sendMyMail($recipient, $yourname, $email, "Your request", $mailcontent);
			}
		}

		// redirect to success-page
		if ($success) {
			if ($smtp['enabled'] === 0 || $smtp['debug'] === 0) {
				echo "<META HTTP-EQUIV=\"refresh\" content=\"0;URL=" . $thankyou . "\">";
			}

			exit;
		} else {
			$fehler['Sendmail'] = "<span class='errormsg' style='display: block;'>The SMTP connection has failed.<br /><span style='text-decoration:underline;'>Possible reasons:</span><br />- Please check the information that you entered in the config.php file. <br />- If you want use an external mailserver (for example Yahoo), please contact your hosting provider for assistance. (Port forwarding is necessary)</span>";
		}
	}
}

// clean post
foreach ($_POST as $key => $value) {
	$_POST[$key] = htmlentities($value, ENT_QUOTES, "UTF-8");
}
?>
<?php




function sendMyMail($fromMail, $fromName, $toMail, $subject, $content, $attachments = array())
{

	$boundary = md5(uniqid(time()));
	$eol = PHP_EOL;

	// header
	$header = "From: =?UTF-8?B?" . base64_encode(stripslashes($fromName)) . "?= <" . $fromMail . ">" . $eol;
	$header .= "Reply-To: <" . $fromMail . ">" . $eol;
	$header .= "MIME-Version: 1.0" . $eol;
	if (is_array($attachments) && 0 < count($attachments)) {
		$header .= "Content-Type: multipart/mixed; boundary=\"" . $boundary . "\"";
	} else {
		$header .= "Content-type: text/plain; charset=utf-8";
	}


	// content with attachments
	if (is_array($attachments) && 0 < count($attachments)) {

		// content
		$message = "--" . $boundary . $eol;
		$message .= "Content-type: text/plain; charset=utf-8" . $eol;
		$message .= "Content-Transfer-Encoding: 8bit" . $eol . $eol;
		$message .= $content . $eol;

		// attachments
		foreach ($attachments as $filename => $filecontent) {
			$filecontent = chunk_split(base64_encode($filecontent));
			$message .= "--" . $boundary . $eol;
			$message .= "Content-Type: application/octet-stream; name=\"" . $filename . "\"" . $eol;
			$message .= "Content-Transfer-Encoding: base64" . $eol;
			$message .= "Content-Disposition: attachment; filename=\"" . $filename . "\"" . $eol . $eol;
			$message .= $filecontent . $eol;
		}
		$message .= "--" . $boundary . "--";
	}
	// content without attachments
	else {
		$message = $content;
	}

	// subject
	$subject = "=?UTF-8?B?" . base64_encode($subject) . "?=";

	// send mail
	return mail($toMail, $subject, $message, $header);
}

?>
<!DOCTYPE html>
<html lang="de-DE">

<head>
	<meta charset="utf-8">
	<meta name="language" content="de" />
	<meta name="description" content="kontaktformular.com" />
	<meta name="revisit" content="After 7 days" />
	<meta name="robots" content="INDEX,FOLLOW" />
	<title>webivot</title>

	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0" />
	<!-- Stylesheet -->
	<link href="assets/styles/style-contact-form.css" rel="stylesheet">


	<link href='https://fonts.googleapis.com/css?family=Heebo:700' rel='stylesheet' type='text/css'>

	<link href="https://fonts.googleapis.com/icon?family=Material+Icons"
      rel="stylesheet">
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
</head>






<div class="containercenter">
	<form id="kontaktformular" class="kontaktformular <?php if (!$cfg['Show_icons']) {
															echo 'no-icons';
														} ?>" action="<?php echo $_SERVER['SCRIPT_NAME']; ?>" method="post" enctype="multipart/form-data">



		<script>
			if (navigator.userAgent.search("Safari") >= 0 && navigator.userAgent.search("Chrome") < 0) {
				document.getElementsByTagName("BODY")[0].className += " safari";
			}
		</script>



		<?php
		if (
			(isset($fehler["Honeypot"]) && $fehler["Honeypot"] != "") ||
			(isset($fehler["Time-out"]) && $fehler["Time-out"] != "") ||
			(isset($fehler["Click_check"]) && $fehler['Click_check'] != "") ||
			(isset($fehler["Links"]) && $fehler['Links'] != "") ||
			(isset($fehler["Badwordfilter"]) && $fehler['Badwordfilter'] != "") ||
			(isset($fehler["Sendmail"]) && $fehler['Sendmail'] != "") ||
			(isset($fehler["upload"]) && $fehler['upload'] != "")
		) {
		?>
			<div class="row first-error-row">
				<div class="col-sm-8">
					<?php if (isset($fehler["Honeypot"]) && $fehler["Honeypot"] != "") {
						echo $fehler["Honeypot"];
					} ?>
					<?php if (isset($fehler["Time-out"]) && $fehler["Time-out"] != "") {
						echo $fehler["Time-out"];
					} ?>
					<?php if (isset($fehler["Click_check"]) && $fehler["Click_check"] != "") {
						echo $fehler["Click_check"];
					} ?>
					<?php if (isset($fehler["Links"]) && $fehler["Links"] != "") {
						echo $fehler["Links"];
					} ?>
					<?php if (isset($fehler["Badwordfilter"]) && $fehler["Badwordfilter"] != "") {
						echo $fehler["Badwordfilter"];
					} ?>
					<?php if (isset($fehler["Sendmail"]) && $fehler["Sendmail"] != "") {
						echo $fehler["Sendmail"];
					} ?>
					<?php if (isset($fehler["upload"]) && $fehler["upload"] != "") {
						echo $fehler["upload"];
					} ?>
				</div>
			</div>
		<?php
		}


		?>





		<div class="row">
			<div class="col-sm-4 marginform<?php echo (isset($_POST['name']) && '' != $_POST['name'] ? 'not-empty-field ' : ''); ?> <?php if ($fehler["name"] != "") {
																															echo 'error';
																														} ?>">
				<label class="control-label" for="border-right5"><i id="user-icon" class="material-icons">account_circle</i><span>Full name*</span></label>
				<input onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> type="text" name="name" class="field" placeholder="" value="<?php echo $_POST['name']; ?>" maxlength="<?php echo $number_of_characters_name; ?>" id="border-right5" />
				<?php if ($fehler["name"] != "") {
					echo $fehler["name"];
				} ?>
			</div>
			<div class="col-sm-4 marginform<?php echo (isset($_POST['email']) && '' != $_POST['email'] ? 'not-empty-field ' : ''); ?> <?php if ($fehler["email"] != "") {
																																echo 'error';
																															} ?>">
				<label class="control-label" for="border-right6"><i id="email-icon" class="material-icons">email</i><span>Email *</span></label>
				<input onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Email" type="<?php if ($cfg['HTML5_error_messages']) {
																																																						echo 'email';
																																																					} else {
																																																						echo 'text';
																																																					} ?>" name="email" class="field" placeholder="" value="<?php echo $_POST['email']; ?>" maxlength="<?php echo $number_of_characters_email; ?>" id="border-right6" />
				<?php if ($fehler["email"] != "") {
					echo $fehler["email"];
				} ?>
			</div>
		</div>




		<div class="row">

			<div class="col-sm-4 marginform<?php echo (isset($_POST['place']) && '' != $_POST['place'] ? 'not-empty-field ' : ''); ?> ">
				<label class="control-label" for="border-right4"><i id="home-icon" class="material-icons">home</i><span>Adress</span></label>
				<input onclick="setActive(this);" onfocus="setActive(this);" aria-label="Ort" type="text" name="place" class="field" placeholder="" value="<?php echo $_POST['place']; ?>" maxlength="<?php echo $number_of_characters_place; ?>" id="border-right4" />

			</div>
			<div class="col-sm-4 <?php echo (isset($_POST['telephone']) && '' != $_POST['telephone'] ? 'not-empty-field ' : ''); ?>">
				<label class="control-label" for="border-right7"><i id="phone-icon" class="material-icons">phone</i><span>Phone</span></label>
				<input onclick="setActive(this);" onfocus="setActive(this);" aria-label="Telephone" type="text" name="telephone" class="field" placeholder="" value="<?php echo $_POST['telephone']; ?>" maxlength="<?php echo $number_of_characters_telephone; ?>" id="border-right7" />
			</div>
		</div>




		<div class="row">
			<div class="col-sm-8 marginform<?php echo (isset($_POST['subject']) && '' != $_POST['subject'] ? 'not-empty-field ' : ''); ?> <?php if ($fehler["subject"] != "") {
																																	echo 'error';
																																} ?>">
				<label class="control-label" for="border-right8"><i id="subject-icon" class="material-icons">edit</i><span>Subject *</span></label>
				<input onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Subject" type="text" name="subject" class="field" placeholder="" value="<?php echo $_POST['subject']; ?>" maxlength="<?php echo $number_of_characters_subject; ?>" id="border-right8" />
				<?php if ($fehler["subject"] != "") {
					echo $fehler["subject"];
				} ?>
			</div>
		</div>




		<div class="row <?php if ($fehler["message"] != "") {
							echo 'error_container';
						} ?>">
			<div class="col-sm-8 message-row marginform<?php echo (isset($_POST['message']) && '' != $_POST['message'] ? 'not-empty-field ' : ''); ?> <?php if ($fehler["message"] != "") {
																																				echo 'error';
																																			} ?>">
				<label class="control-label textarea-label" for="border-right9"><i id="message-icon" class="material-icons">chat</i><span>Message *</span></label>
				<textarea onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Message" name="message" class="field" rows="5" placeholder="" id="border-right9"><?php echo $_POST['message']; ?></textarea>
				<?php if ($fehler["message"] != "") {
					echo $fehler["message"];
				} ?>
			</div>
		</div>








		<?php
		// -------------------- FILEUPLOAD START ----------------------
		if (0 < $cfg['NUM_ATTACHMENT_FIELDS']) {
			echo '<div class="row upload-row">
						<div class="col-sm-8">
							<label class="control-label" for="upload_field0"><i id="fileupload-icon" class="material-icons">file_download</i></label>
							<div id="files">';
			for ($i = 0; $i < $cfg['NUM_ATTACHMENT_FIELDS']; $i++) {
				echo '<div><label for="upload_field' . $i . '">
										<span class="file_button">File</span>
										<span class="file_name" id="upload_field' . $i . '_flename"><span style="color:#A6A6A6;">File Upload</span></span>
										<input onchange="document.getElementById(\'upload_field' . $i . '_flename\').innerHTML = getFilename(this);" aria-label="File Upload" type="file" size=12 name="f[]" id="upload_field' . $i . '"/>
									</label></div>';
			}
			echo '		</div>
						</div>
					</div>';
		}
		// -------------------- FILEUPLOAD END ----------------------
		?>






		<?php
		// -------------------- SPAMPROTECTION START ----------------------

		if ($cfg['Honeypot']) { ?>
			<div style="height: 2px; overflow: hidden;">
				<label style="margin-top: 10px;">The following field must remain empty for the message to be sent!</label>
				<div style="margin-top: 10px;"><input type="email" name="mail" value="" /></div>
			</div>
		<?php }

		if ($cfg['Time-out']) { ?>
			<input type="hidden" name="chkspmtm" value="<?php echo time(); ?>" />
		<?php }

		if ($cfg['Click_check']) { ?>
			<input type="hidden" name="chkspmkc" value="chkspmbt" />
		<?php }


		if ($cfg['Security_code']) { ?>
			<div class="row captcha-row <?php if ($fehler["captcha"] != "") {
											echo 'error_container';
										} ?>">
				<div class="col-sm-8 <?php if ($fehler["captcha"] != "") {
											echo 'error';
										} ?>">
					<label class="control-label" for="answer2"><i id="securitycode-icon" class="material-icons">lock</i></label>
					<div>
						<img aria-label="Captcha" src="captcha/captcha.php" alt="Security_code" title="kontaktformular.com-sicherheitscode" id="captcha" />
						<a href="javascript:void(0);" onclick="javascript:document.getElementById('captcha').src='captcha/captcha.php?'+Math.random();cursor:pointer;">
							<span class="captchareload"><i style="color:grey;" class="material-icons">loop</i></span>
						</a>
					</div>
					<div class="captcha-input-div">
						<label class="control-label" for="answer2"><span style="width:250px;">Please enter security code. *</span></label>
						<input onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Eingabe" id="answer2" placeholder="" type="text" name="sicherheitscode" maxlength="150" class="field<?php if ($fehler["captcha"] != "") {
																																																																														echo ' errordesignfields';
																																																																													} ?>" />
						<?php if ($fehler["captcha"] != "") {
							echo $fehler["captcha"];
						} ?>
					</div>
				</div>
			</div>
			<div style="margin-bottom:30px;"></div>


		<?php }

		if ($cfg['Security_question']) { ?>

			<div class="row question-row <?php if ($fehler["q_id12"] != "") {
												echo 'error_container';
											} ?>">
				<div class="col-sm-8 <?php if ($fehler["q_id12"] != "") {
											echo 'error';
										} ?>">
					<label class="control-label" for="answer"><i id="securityquestion-icon" class="material-icons">lock</i></label>
					<div aria-label="Sicherheitsfrage">
						<?php echo $q[1]; ?>
						<input type="hidden" name="q_id" value="<?php echo $q[0]; ?>" />
					</div>
					<div class="question-input-div">
						<label class="control-label" for="answer"><span>Please answer the question. *</span></label>
						<input onclick="setActive(this);" onfocus="setActive(this);" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Antwort" id="answer" placeholder="" type="text" class="field<?php if ($fehler["q_id12"] != "") {
																																																																				echo ' errordesignfields';
																																																																			} ?>" name="q" />
						<?php if ($fehler["q_id12"] != "") {
							echo $fehler["q_id12"];
						} ?>
					</div>
				</div>
			</div>
			<div style="margin-bottom:30px;"></div>



		<?php }

		// -------------------- SPAMPROTECTION END ----------------------
		{ ?>






		<?php }

		// -------------------- MAIL-COPY START ----------------------

		if (1 == $cfg['Send_copy']) { ?>
			<div class="row checkbox-row">
				<div class="col-sm-8">
					<label for="inlineCheckbox11" class="checkbox-inline">
						<i id="email-icon-position-2" class="material-icons material-icons-pos12">email</i> <i id="mailcopy-checkbox-icon" class="material-icons material-icons-pos2 <?php echo ($_POST['mail-copy'] == '1' ? 'checked' : ''); ?>"><?php echo ($_POST['mail-copy'] == '1' ? 'check_box' : 'check_box_outline_blank'); ?></i>
						<input style="display: none;" type="checkbox" onclick="
																		document.getElementById('mailcopy-checkbox-icon').innerHTML = (this.checked ? 'check_box' : 'check_box_outline_blank'); 
																		(this.checked ? document.getElementById('mailcopy-checkbox-icon').classList.add('checked') : document.getElementById('mailcopy-checkbox-icon').classList.remove('checked'));
																	" aria-label="Email-Kopie senden" id="inlineCheckbox11" name="mail-copy" value="1" <?php if (isset($_POST['mail-copy']) && $_POST['mail-copy'] == '1') echo (' checked="checked" '); ?>>
						<div><span>I want a copy of this email.</span></div>
					</label>
				</div>
			</div>
		<?php }

		// -------------------- MAIL-COPY END ----------------------


		// -------------------- DATAPROTECTION START ----------------------

		if ($cfg['DATA_PRIVACY_POLICY']) { ?>
			<div class="row checkbox-row <?php if ($fehler["data_protection"] != "") {
												echo 'error_container';
											} ?>">
				<div class="col-sm-8 <?php if ($fehler["data_protection"] != "") {
											echo 'error';
										} ?>">
					<label for="inlineCheckbox12" class="checkbox-inline">
						<i id="dataprotection-icon" class="material-icons material-icons-pos1">security</i><i id="dataprotection-checkbox-icon" class="material-icons material-icons-pos2 <?php echo ($_POST['data_protection'] == 'accepted' ? 'checked' : ''); ?>"><?php echo ($_POST['data_protection'] == 'accepted' ? 'check_box' : 'check_box_outline_blank'); ?></i>
						<input style="<?php echo ($cfg['Show_icons'] ? 'left:55px;' : ''); ?>" type="checkbox" onclick="																		document.getElementById('dataprotection-checkbox-icon').innerHTML = (this.checked ? 'check_box' : 'check_box_outline_blank'); 
																		(this.checked ? document.getElementById('dataprotection-checkbox-icon').classList.add('checked') : document.getElementById('dataprotection-checkbox-icon').classList.remove('checked'));
																	" <?php if ($cfg['HTML5_error_messages']) { ?> required <?php } else { ?> onchange="checkField(this)" <?php } ?> aria-label="Datenschutz" id="inlineCheckbox12" name="data_protection" value="accepted" <?php if ($_POST['data_protection'] == 'accepted') echo (' checked="checked" '); ?>>
						<div> <a href="<?php echo "$dataprivacypolicy"; ?>" target="_blank">I accept the data privacy policy.</a>&nbsp;*</div>
					</label>
					<?php if ($fehler["data_protection"] != "") {
						echo $fehler["data_protection"];
					} ?>
				</div>
			</div>
			<div style="margin-bottom:12px;"></div>
		<?php }

		// -------------------- DATAPROTECTION END ----------------------

		?>


		<div class="row" id="send">
			<div class="col-sm-8" style="margin-left:2px;">

				<br /><br /><b>Note:</b> Fields with <span class="pflichtfeld">*</span> are required.
				<br />
				<br />
				<input type="submit" class="senden" name="en-us-kf-km" value="Send custom quote" />

				<div style="text-align:center;"><br /><br />
					<!-- Do NOT remove this copyright notice! --><a href="https://www.kontaktformular.com/en" title="kontaktformular.com" style="text-decoration: none;color:#000000;font-size:13px;" target="_blank"></a>
				</div>

			</div>
		</div>





		<?php if ($cfg['Click_check']) { ?>
			<script type="text/javascript">
				function chkspmkcfnk() {
					document.getElementsByName('chkspmkc')[0].value = 'chkspmhm';
				}
				document.getElementsByName('en-us-kf-km')[0].addEventListener('mouseenter', chkspmkcfnk);
				document.getElementsByName('en-us-kf-km')[0].addEventListener('touchstart', chkspmkcfnk);
			</script>
		<?php } ?>
		<script type="text/javascript">
			var formSubmit = false;

			// set class kontaktformular-validate for form if user wants to send the form > so the invalid-styles only appears after validation
			function setValidationStyles() {
				document.getElementById('kontaktformular').classList.add('kontaktformular-validate');
				formSubmit = true;
			}
			document.getElementsByName('en-us-kf-km')[0].addEventListener('click', setValidationStyles);
			document.getElementById('kontaktformular').addEventListener('submit', setValidationStyles);

			// add readonly-function to selectboxes
			let readonlyFields = document.getElementsByClassName('readonly');
			for (let i = 0; i < readonlyFields.length; i++) {
				readonlyFields[i].addEventListener('keydown', function(e) {
					e.preventDefault();
				});
				readonlyFields[i].addEventListener('paste', function(e) {
					e.preventDefault();
				});
			}
		</script>
		<?php if (!$cfg['HTML5_error_messages']) { ?>
			<script type="text/javascript">
				// set class kontaktformular-validate for form if user wants to send the form > so the invalid-styles only appears after validation
				function checkField(field) {

					// email-field > do special check
					if ('email' == field.getAttribute('type') || 'email' == field.getAttribute('name')) {

						// field is correct > remove error
						if ('' != field.value && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(field.value)) {

							// remove error-class
							field.parentNode.classList.remove("error");
							field.nextElementSibling.style.display = 'none';

							// remove class error_container from parent-elements
							field.parentNode.parentNode.parentNode.classList.remove("error_container");
							field.parentNode.parentNode.classList.remove("error_container");
							field.parentNode.classList.remove("error_container");
						}
					}

					// no email
					else {

						// field is filled
						if ('' != field.value) {

							// if field is checkbox or security-row: go to parentNode and do things because checkbox is in label-element
							if (
								'checkbox' == field.getAttribute('type') ||
								field.parentNode.classList.contains('question-input-div') ||
								field.parentNode.classList.contains('captcha-input-div')
							) {
								field.parentNode.parentNode.classList.remove("error");

								// hide error for checkboxes
								if (field.parentNode.nextElementSibling) {
									field.parentNode.nextElementSibling.style.display = 'none';
								}
								// hide error for security-rows
								if (field.nextElementSibling && 'errormsg' == field.nextElementSibling.getAttribute('class')) {
									field.nextElementSibling.style.display = 'none';
								}
							}
							// field is no checkbox and no security-row: do things with field
							else {
								field.parentNode.classList.remove("error");
								if (field.nextElementSibling && 'errormsg' == field.nextElementSibling.getAttribute('class')) {
									field.nextElementSibling.style.display = 'none';
								}
							}

							// remove class error_container from parent-elements
							field.parentNode.parentNode.parentNode.classList.remove("error_container");
							field.parentNode.parentNode.classList.remove("error_container");
							field.parentNode.classList.remove("error_container");
						}
					}

				}
			</script>
		<?php } else { ?>
			<script>
				document.addEventListener('invalid', function(e) {
					var field = e.target;

					// if field is checkbox or security-row: go to parentNode and do things because checkbox is in label-element
					if ('checkbox' == field.getAttribute('type') ||
						field.parentNode.classList.contains('question-input-div') ||
						field.parentNode.classList.contains('captcha-input-div')
					) {
						field.parentNode.parentNode.classList.add("error");
					}
					// field is no checkbox and no security-row: do things with field
					else {
						field.parentNode.classList.add("error");
					}

					field.setAttribute('onchange', 'checkField(this)');
				}, true);


				// checks if we can remove invalid-styles
				function checkField(field) {

					if (field.checkValidity()) {

						// if field is checkbox or security-row: go to parentNode and do things because checkbox is in label-element
						if ('checkbox' == field.getAttribute('type') ||
							field.parentNode.classList.contains('question-input-div') ||
							field.parentNode.classList.contains('captcha-input-div')
						) {
							field.parentNode.parentNode.classList.remove("error");
						}
						// field is no checkbox and no security-row: do things with field
						else {
							field.parentNode.classList.remove("error");
						}
					}
				}
			</script>
		<?php } ?>
		<script>
			// --------------------- field active / inactive

			// set active-class to field 
			function setActive(element) {

				<?php if ($cfg['HTML5_error_messages']) { ?>
					// ignore function-call if the browser set focus because of HTML5-errors on form-submit and the field is a selectbox
					if (formSubmit && element.classList.contains('select-input')) {

						// set formSubmit to false so we know that the function is not called from browser (needed for HTML5-errors which create a focus-problem for selectboxes)
						formSubmit = false;
						return;
					}

					// set formSubmit to false so we know that the function is not called from browser (needed for HTML5-errors which create a focus-problem for selectboxes)
					formSubmit = false;
				<?php } ?>

				// set onblur-function to set field inactive
				element.focus();
				element.setAttribute('onblur', 'setInactive(this)');

				// set active-class to parent-div
				var parentDiv = getParentDiv(element);

				// if field is security-row: go to parentNode and do things
				if (
					parentDiv.classList.contains('question-input-div') ||
					parentDiv.classList.contains('captcha-input-div')
				) {
					parentDiv.parentNode.classList.add('active-field');
				}
				// field is no security-row: do things with field
				else {
					parentDiv.classList.add('active-field');
				}

				// field is a selectBox > mark selected option
				if (element.classList.contains('select-input') && '' != element.value) {
					var selectBox = getSiblingUl(element);
					var selectBoxOptions = selectBox.childNodes;
					for (i = 0; i < selectBoxOptions.length; ++i) {
						if ('li' == selectBoxOptions[i].nodeName.toLowerCase()) {
							if (element.value == selectBoxOptions[i].innerHTML) {
								selectBoxOptions[i].classList.add('active');
							} else {
								selectBoxOptions[i].classList.remove('active');
							}
						}
					}
				}
			}

			// set field inactive
			function setInactive(element) {

				// remove active-class from parent-div
				var parentDiv = getParentDiv(element);

				// if field is security-row: go to parentNode and do things
				if (
					parentDiv.classList.contains('question-input-div') ||
					parentDiv.classList.contains('captcha-input-div')
				) {
					parentDiv.parentNode.classList.remove('active-field');
				}
				// field is no security-row: do things with field
				else {
					parentDiv.classList.remove('active-field');
				}

				// field contains string > set not-empty-class
				if ('' != element.value) {
					parentDiv.classList.add('not-empty-field');
				}
				// field doesn't contain string > remove not-empty-class
				else {
					parentDiv.classList.remove('not-empty-field');
				}
			}


			// set selectBox-eventlistener
			var selectBoxOptions = document.querySelectorAll('.select-box li');
			for (i = 0; i < selectBoxOptions.length; ++i) {
				selectBoxOptions[i].setAttribute('onmousedown', 'selectOption(this)');
			}

			// selects an electbox-option
			function selectOption(element) {

				var field = getSiblingInput(element);
				var selectedValue = (element.classList.contains('placeholder') ? '' : element.innerHTML);

				// call check-function if field-content has changed and set selectedValue
				if (field.value != selectedValue) {
					field.value = selectedValue;
					checkField(field);
				}
			}







			// set textarea-eventlistener
			var textareas = document.getElementsByTagName('textarea');
			for (i = 0; i < textareas.length; ++i) {
				textareas[i].setAttribute('oninput', 'updateTextareaHeight(this)');

				var textareaPaddingTop = parseFloat(window.getComputedStyle(textareas[i]).getPropertyValue('padding-top'), 10);
				var textareaPaddingBottom = parseFloat(window.getComputedStyle(textareas[i]).getPropertyValue('padding-bottom'), 10);
				var textareaHeight = textareas[i].scrollHeight - textareaPaddingTop - textareaPaddingBottom;

				textareas[i].setAttribute('data-original_height', textareaHeight);
				textareas[i].style.overflow = 'hidden';
				textareas[i].style.boxSizing = 'border-box';
				updateTextareaHeight(textareas[i]);
			}

			// updates the height of the textarea
			function updateTextareaHeight(element) {

				// get original-height of textarea
				var originalHeight = element.getAttribute('data-original_height');

				// clone textarea, set it 1px and insert it into dom
				var tempCloneElement = element.cloneNode(true);
				tempCloneElement.style.height = "1px";
				element.after(tempCloneElement);

				// get new calculated height					
				var newHeight = (tempCloneElement.scrollHeight);

				// remove temp clone-element to clean up
				tempCloneElement.remove();

				// original-height is smaller > set new height										
				if (originalHeight < newHeight) {
					element.style.height = newHeight + "px";
				} else {
					element.style.height = originalHeight + "px";
				}
			}




			// --------------------- helper

			// get the closest parent-div
			function getParentDiv(element) {
				while (element && element.parentNode) {
					element = element.parentNode;
					if (element.tagName && 'div' == element.tagName.toLowerCase()) {
						return element;
					}
				}
				return null;
			}

			// get the closest sibling-input
			function getSiblingInput(element) {
				element = element.parentNode;
				while (element && element.previousSibling) {
					element = element.previousSibling;
					if (element.tagName && 'input' == element.tagName.toLowerCase()) {
						return element;
					}
				}
				return null;
			}

			// get the closest sibling-ul
			function getSiblingUl(element) {
				while (element && element.nextSibling) {
					element = element.nextSibling;
					if (element.tagName && 'ul' == element.tagName.toLowerCase()) {
						return element;
					}
				}
				return null;
			}

			// return the filename of the selected file in the given file-input
			function getFilename(element) {
				if ('' != element.value) {
					var startIndex = (element.value.indexOf('\\') >= 0 ? element.value.lastIndexOf('\\') : element.value.lastIndexOf('/'));
					var filename = element.value.substring(startIndex);
					if (filename.indexOf('\\') === 0 || filename.indexOf('/') === 0) {
						filename = filename.substring(1);
					}
					return filename;
				} else {
					return '&nbsp;'
				}
			}
		</script>
	</form>
</div>

</html>