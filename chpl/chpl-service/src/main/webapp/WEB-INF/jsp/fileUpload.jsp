<% String rootContext = request.getRequestURL().toString().replace("/FileUpload", ""); %>

<html>
<head>
	<title>File Upload Testing Page</title>
</head>

<body>
<h1>Select a file. Must be of type XLS or CSV. Max 5MB</h1>
<form method="post" action="certified_product/upload" enctype="multipart/form-data">
	ACB ID: <input type="text" name="acbId" /><br/>
    <input type="file" name="file"/><br/>
    <input type="submit"/>
</form>

</html>