package com.github.caryyu.ssso;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.encryption.DecryptionException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLStatusException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

import static org.springframework.security.saml.util.SAMLUtil.isDateTimeSkewValid;

public class OneLoginSingleLogoutProfileImpl extends SingleLogoutProfileImpl {
    @Override
    public boolean processLogoutRequest(SAMLMessageContext context, SAMLCredential credential) throws SAMLException {
        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (message == null || !(message instanceof LogoutRequest)) {
            throw new SAMLException("Message is not of a LogoutRequest object type");
        }

        LogoutRequest logoutRequest = (LogoutRequest) message;

        // Make sure request was authenticated if required, authentication is done as part of the binding processing
        if (!context.isInboundSAMLMessageAuthenticated() && context.getLocalExtendedMetadata().isRequireLogoutRequestSigned()) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "LogoutRequest is required to be signed by the entity policy");
        }

        // Verify destination
        try {
            verifyEndpoint(context.getLocalEntityEndpoint(), logoutRequest.getDestination());
        } catch (SAMLException e) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "Destination of the LogoutRequest does not match any of the single logout endpoints");
        }

        // Verify issuer
        try {
            if (logoutRequest.getIssuer() != null) {
                Issuer issuer = logoutRequest.getIssuer();
                verifyIssuer(issuer, context);
            }
        } catch (SAMLException e) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "Issuer of the LogoutRequest is unknown");
        }

        // Verify issue time
        DateTime time = logoutRequest.getIssueInstant();
        if (!isDateTimeSkewValid(getResponseSkew(), time)) {
            throw new SAMLStatusException(StatusCode.REQUESTER_URI, "LogoutRequest issue instant is either too old or with date in the future");
        }

        // Check whether any user is logged in
        if (credential == null) {
            throw new SAMLStatusException(StatusCode.UNKNOWN_PRINCIPAL_URI, "No user is logged in");
        }

        // Find index for which the logout is requested
        boolean indexFound = false;
        if (logoutRequest.getSessionIndexes() != null && logoutRequest.getSessionIndexes().size() > 0) {
            for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
                String statementIndex = statement.getSessionIndex();
                if (statementIndex != null) {
                    for (SessionIndex index : logoutRequest.getSessionIndexes()) {
                        if (statementIndex.equals(index.getSessionIndex())) {
                            indexFound = true;
                        }
                    }
                }
            }
        } else {
            indexFound = true;
        }

        // Fail if sessionIndex is not found in any assertion
        if (!indexFound) {

            // Check logout request still valid and store request
            //if (logoutRequest.getNotOnOrAfter() != null) {
            // TODO store request for assertions possibly arriving later
            //}

            throw new SAMLStatusException(StatusCode.REQUESTER_URI, "The SessionIndex was not found");

        }

        try {
            // Fail if NameId doesn't correspond to the currently logged user
            NameID nameID = getNameID(context, logoutRequest);
            if (nameID == null || !equalsNameID(credential.getNameID(), nameID)) {
                throw new SAMLStatusException(StatusCode.UNKNOWN_PRINCIPAL_URI, "The requested NameID is invalid");
            }
        } catch (DecryptionException e) {
            throw new SAMLStatusException(StatusCode.RESPONDER_URI, "The NameID can't be decrypted", e);
        }

        return true;

    }

    private boolean equalsNameID(NameID a, NameID b) {
        boolean equals = !differ(a.getSPProvidedID(), b.getSPProvidedID());
        equals = equals && !differ(a.getValue(), b.getValue());
        // Here's a bug that credential's different from this one in logout request scenario
//        equals = equals && !differ(a.getFormat(), b.getFormat());
        equals = equals && !differ(a.getNameQualifier(), b.getNameQualifier());
        equals = equals && !differ(a.getSPNameQualifier(), b.getSPNameQualifier());
        equals = equals && !differ(a.getSPProvidedID(), b.getSPProvidedID());
        return equals;
    }

    private boolean differ(Object a, Object b) {
        if (a == null) {
            return b != null;
        } else {
            return !a.equals(b);
        }
    }
}
