<%@ page contentType="text/javascript; charset=UTF-8"%>
<%out.print("jsonpcallback({'lt':'");%>${loginTicket}<%out.print ("','execution':'");%>${flowExecutionKey}<%out.print("'})");%>
