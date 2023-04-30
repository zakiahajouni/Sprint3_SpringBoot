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
    <title>Update Motor</title>
</head>
<body>
<div class="container mt-5">
    <div class="card-body">
        <form action="updateMotor" method="post">
            <div class="form-group">
                <label class="control-label">ID Motor :</label>
                <input type="text" name="idMotor" value="${motor.idMotor}"
                       readonly class="form-control"/>
            </div>
            <div class="form-group">
                <label class="control-label">Name :</label>
                <input type="text" name="nameMotor" value="${motor.nameMotor}"
                       class="form-control"/>
            </div>
            <div class="form-group">
                <label class="control-label">Price :</label>
                <input type="text" name="priceMotor" value="${motor.priceMotor}"
                       class="form-control"/>
            </div>
            <div class="form-group">
                <label class="control-label"> Date of creation :</label>
                <fmt:formatDate pattern="yyyy-MM-dd" value="${motor.dateCreation}"
                                var="formatDate" />
                <input type="date" name="date" value="${formatDate}" class="form-control"/>
                <div class="form-group">
                    <label class="control-label">Maximum Speed :</label>
                    <input type="text" name="maxSpeedMotor" value="${motor.maxSpeedMotor}"
                           class="form-control"/>
                </div>
                <div class="form-group">
                    <label class="control-label">Color :</label>
                    <input type="text" name="colorMotor" value="${motor.colorMotor}"
                           class="form-control"/>
                </div>
            </div>
            <div>
                <button type="submit" class="btn btn-primary">Update</button>
            </div>
        </form>
    </div>
    <br/>
    <br/>
    <a href="ListeMotors">List of Motors</a>
</div>
</body>
</html>