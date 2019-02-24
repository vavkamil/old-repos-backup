<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">

<html>
	<head>
		<title>RFI example</title>
	</head>

	<body>
		<h1>RFI test</h1>
		<?php
			// RFI test
			$rfi = $_GET['rfi'];
			include $rfi.".html";
		?>
	</body>
</html>