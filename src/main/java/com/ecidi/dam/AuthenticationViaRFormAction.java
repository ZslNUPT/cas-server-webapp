package com.ecidi.dam;

import java.util.Iterator;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.Message;
import org.jasig.cas.authentication.AuthenticationException;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.ticket.TicketCreationException;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.jasig.cas.web.flow.AuthenticationViaFormAction;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.util.StringUtils;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Zuosl
 * @date 2017/11/21
 */

public class AuthenticationViaRFormAction {

    public static final String SUCCESS = "success";
    public static final String SUCCESS_WITH_WARNINGS = "successWithWarnings";
    public static final String WARN = "warn";
    public static final String AUTHENTICATION_FAILURE = "authenticationFailure";
    public static final String ERROR = "error";
    private CredentialsBinder credentialsBinder;
    @NotNull
    private CentralAuthenticationService centralAuthenticationService;
    @NotNull
    private TicketRegistry ticketRegistry;
    @NotNull
    private CookieGenerator warnCookieGenerator;
    private boolean hasWarningMessages;
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public AuthenticationViaRFormAction() {
    }

    public final void doBind(RequestContext context, Credential credential) throws Exception {
        HttpServletRequest request = WebUtils.getHttpServletRequest(context);
        if (this.credentialsBinder != null && this.credentialsBinder.supports(credential.getClass())) {
            this.credentialsBinder.bind(request, credential);
        }
    }

    public final Event submit(final RequestContext context, final Credential credential, final MessageContext messageContext) throws Exception { // Validate login ticket
        final String authoritativeLoginTicket = WebUtils.getLoginTicketFromFlowScope(context);
        final String providedLoginTicket = WebUtils.getLoginTicketFromRequest(context);
        if (!authoritativeLoginTicket.equals(providedLoginTicket)) {
            logger.warn("Invalid login ticket {}", providedLoginTicket);
            messageContext.addMessage(new MessageBuilder().code("error.invalid.loginticket").build());
            context.getFlowScope().put("ret", -1);
            context.getFlowScope().put("msg", "LT过期，请重新登录!");
        }
        try {
            final String tgtId = this.centralAuthenticationService.createTicketGrantingTicket(credential);
            WebUtils.putTicketGrantingTicketInFlowScope(context, tgtId);
            final Service service = WebUtils.getService(context);
            final String serviceTicketId = this.centralAuthenticationService.grantServiceTicket(tgtId, service);
            WebUtils.putServiceTicketInRequestScope(context, serviceTicketId);
            context.getFlowScope().put("ticket", serviceTicketId);
            return newEvent(SUCCESS);
        } catch (final AuthenticationException e) {
            context.getFlowScope().put("ret", -2);
            context.getFlowScope().put("msg", "用户名密码错误，请重新登录!");
            return newEvent(SUCCESS);
        } catch (final Exception e) {
            context.getFlowScope().put("ret", -3);
            context.getFlowScope().put("msg", "系统内部错误，请稍后登录!");
            return newEvent(SUCCESS);
        }
    }

    private void putWarnCookieIfRequestParameterPresent(RequestContext context) {
        HttpServletResponse response = WebUtils.getHttpServletResponse(context);
        if (StringUtils.hasText(context.getExternalContext().getRequestParameterMap().get("warn"))) {
            this.warnCookieGenerator.addCookie(response, "true");
        } else {
            this.warnCookieGenerator.removeCookie(response);
        }

    }

    private AuthenticationException getAuthenticationExceptionAsCause(TicketException e) {
        return (AuthenticationException) e.getCause();
    }

    private Event newEvent(String id) {
        return new Event(this, id);
    }

    private Event newEvent(String id, Exception error) {
        return new Event(this, id, new LocalAttributeMap("error", error));
    }

    public final void setCentralAuthenticationService(CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }

    public void setTicketRegistry(TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;
    }

    public final void setCredentialsBinder(CredentialsBinder credentialsBinder) {
        this.credentialsBinder = credentialsBinder;
    }

    public final void setWarnCookieGenerator(CookieGenerator warnCookieGenerator) {
        this.warnCookieGenerator = warnCookieGenerator;
    }

    private void addWarningToContext(MessageContext context, Message warning) {
        MessageBuilder builder = (new MessageBuilder()).warning().code(warning.getCode()).defaultText(warning.getDefaultMessage()).args(warning.getParams());
        context.addMessage(builder.build());
        this.hasWarningMessages = true;
    }


}
