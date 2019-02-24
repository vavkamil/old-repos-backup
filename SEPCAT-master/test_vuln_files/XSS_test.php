<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">

<html>
	<head>
		<title>XSS example</title>
	</head>

	<body>
		<h1>XSS test</h1>
		<?php
			// XSS test
			$name = $_GET['name'];
			$name = htmlspecialchars($name);
			$age = $_GET['age'];

			print('Hello ' . $name . ', you are ' . $age . ' years old.');
		?>
	</body>
</html>