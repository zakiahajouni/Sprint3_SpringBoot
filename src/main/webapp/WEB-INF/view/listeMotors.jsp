<%@ page language="java" contentType="text/html; charset=windows-1256"
         pageEncoding="windows-1256"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<link rel="stylesheet" type="text/css"
      href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" />
<c:url value="/css/main.css" var="jstlCss" />
<link href="${jstlCss}" rel="stylesheet" />
<script type="text/javascript"
        src="webjars/bootstrap/4.3.1/js/bootstrap.min.js"></script>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=windows-1256">
    <title>List of motors</title>
</head>
<body>
<div class="container mt-5">
    <div class="card">
        <div class="card-header">
            List of motors
        </div>
        <div class="card-body">

            <table class="table table-striped">
                <tr>
        <th>ID</th><th>Name</th><th>Price</th><th>Date of creation</th><th>
        Maximum Speed</th><th>Color

    </th><th>Delete<th>Edit</th>
    </tr>
    <c:forEach items="${motors}" var="m">
        <tr>
            <td>${m.idMotor }</td>
            <td>${m.nameMotor }</td>
            <td>${m.priceMotor }</td>
            <td><fmt:formatDate pattern="dd/MM/yyyy"
                                value="${m.dateCreation}" /></td>
            <td>${m.maxSpeedMotor}</td>
            <td>${m. colorMotor}</td>

            <td><a onclick="return confirm('Are you sure ?')"
                   href="supprimerMotor?id=${m.idMotor }">Delete</a></td>
            <td><a href="modifierMotor?id=${m.idMotor }">Edit</a></td>
        </tr>
    </c:forEach>
</table>
</body>
</html>