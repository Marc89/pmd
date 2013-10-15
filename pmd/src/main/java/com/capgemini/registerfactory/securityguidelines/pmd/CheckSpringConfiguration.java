package com.capgemini.registerfactory.securityguidelines.pmd;

import java.io.StringWriter;
import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractDomXmlRule;
import net.sourceforge.pmd.lang.xml.rule.XmlRuleViolationFactory;

import org.w3c.dom.Document;

public class CheckSpringConfiguration extends AbstractDomXmlRule {
	
	//sicherheit.xml
	final String AUFRUF_KONTEXT_PATTERN = "/x:beans/x:bean[@id=\"aufrufKontextInterceptor\" and @class=\"de.bund.bva.pliscommon.aufrufkontext.service.StelltAufrufKontextBereitInterceptor\" and x:property[@name=\"aufrufKontextVerwalter\" and @ref=\"aufrufKontextVerwalter\"] and x:property[@name=\"aufrufKontextFactory\" and @ref=\"aufrufKontextFactory\"]]";
	final String GESICHERT_INTERCEPTOR_PATTERN = "/x:beans/x:bean[@id=\"gesichertInterceptor\" and @class=\"de.bund.bva.pliscommon.sicherheit.annotation.GesichertInterceptor\" and x:property[@name=\"sicherheit\" and @ref=\"sicherheit\"] and x:property[@name=\"sicherheitAttributeSource\" and x:bean[@class=\"de.bund.bva.pliscommon.sicherheit.annotation.AnnotationSicherheitAttributeSource\"]]]";
	final String LOGGING_KONTEXT_INTERCEPTOR_PATTERN = "/x:beans/x:bean[@id=\"loggingKontextIntercepter\" and @class=\"de.bund.bva.pliscommon.aufrufkontext.service.StelltLoggingKontextBereitInterceptor\" ]";
	final String AOP_CONFIG_PATTERN = "/x:beans/aop:config[aop:pointcut[@id=\"loggingKontextPointcut\" and @expression=\"@annotation(de.bund.bva.pliscommon.aufrufkontext.service.StelltLoggingKontextBereit) || @within(de.bund.bva.pliscommon.aufrufkontext.service.StelltLoggingKontextBereit)\"] and aop:pointcut[@id=\"aufrufKontextPointcut\" and @expression=\"@annotation(de.bund.bva.pliscommon.aufrufkontext.service.StelltAufrufKontextBereit) || @within(de.bund.bva.pliscommon.aufrufkontext.service.StelltAufrufKontextBereit)\"] and aop:pointcut[@id=\"gesichertPointcut\" and @expression=\"@annotation(de.bund.bva.pliscommon.sicherheit.annotation.Gesichert) || @within(de.bund.bva.pliscommon.sicherheit.annotation.Gesichert)\"] and aop:advisor[@pointcut-ref=\"loggingKontextPointcut\" and @advice-ref=\"loggingKontextIntercepter\" and @order=\"50\"] and aop:advisor[@pointcut-ref=\"aufrufKontextPointcut\" and @advice-ref=\"aufrufKontextInterceptor\" and @order=\"50\"] and aop:advisor[@pointcut-ref=\"gesichertPointcut\" and @advice-ref=\"gesichertInterceptor\" and @order=\"100\"]]";
	final String AUFRUF_KONTEXT_FACTORY_PATTERN = "/x:beans/x:bean[@id=\"aufrufKontextFactory\" and  @class=\"de.bund.bva.pliscommon.aufrufkontext.impl.AufrufKontextFactoryImpl\" and x:property[@name=\"aufrufKontextKlasse\" and @value=\"de.bund.bva.pliscommon.kontext.BehoerdenverzeichnisAufrufKontext\"]]"; 
	final String AUFRUF_KONTEXT_VERWALTER_PATTERN = "/x:beans/x:bean[@id=\"aufrufKontextVerwalter\" and @scope=\"request\" and @class=\"de.bund.bva.pliscommon.aufrufkontext.impl.AufrufKontextVerwalterImpl\" and aop:scoped-proxy]";
	final String SICHERHEIT_ADMIN_PATTERN = "/x:beans/x:bean[@id=\"sicherheitAdmin\" and @class=\"de.bund.bva.pliscommon.sicherheit.impl.SicherheitAdminImpl\" and x:property [@name=\"accessManager\" and @ref=\"camsAccessManager\"]]";
	final String SICHERHEIT_PATTERN = "/x:beans/x:bean[@id=\"sicherheit\" and @class=\"de.bund.bva.pliscommon.sicherheit.impl.SicherheitImpl\" and x:property[@name=\"rollenRechteDateiPfad\" and @value=\"/resources/sicherheit/rollenrechte.xml\"] and x:property[@name=\"aufrufKontextVerwalter\" and @ref=\"aufrufKontextVerwalter\"] and x:property[@name=\"accessManager\" and @ref=\"camsAccessManager\"] and x:property[@name=\"konfiguration\" and @ref=\"konfiguration\"] and x:property[@name=\"aufrufKontextFactory\" and  @ref=\"aufrufKontextFactory\"]]";
	final String CAMS_ACCESS_MANAGER_PATTERN = "/x:beans/x:bean[@id=\"camsAccessManager\" and @class=\"de.bund.bva.pliscommon.sicherheit.impl.CamsAccessManagerImpl\" and @depends-on=\"konfiguration\" and x:constructor-arg [@index=\"0\" and x:ref[@bean=\"camsConfiguration\"]] and x:constructor-arg [@index=\"1\" and x:ref[@bean=\"konfiguration\"]]]";
	final String CAMS_CONFIGURATION_PATTERN = "/x:beans/x:bean[@id=\"camsConfiguration\" and @class=\"org.springframework.core.io.ClassPathResource\" and x:constructor-arg[@value=\"/config/cams-webagent.conf\"]]";

	//LDAP-Konfiguration
	final String CONTEXT_SOURCE_PATTERN = "/x:beans/x:bean[@id=\"contextSource\" and @class=\"org.springframework.ldap.pool.factory.PoolingContextSource\"\tand x:property[@name=\"contextSource\"\tand x:bean[@class=\"org.springframework.ldap.core.support.LdapContextSource\" and x:property[@name=\"url\" and @value=\"${ldap.url}\"] and x:property[@name=\"userDn\" and @value=\"${ldap.userdn}\"] and x:property[@name=\"password\" and @value=\"${ldap.password}\"] and x:property[@name=\"base\" and @value=\"${ldap.basedn}\"] and x:property[@name=\"pooled\" and @value=\"false\"]]]\tand x:property[@name=\"dirContextValidator\" and x:bean[@class=\"org.springframework.ldap.pool.validation.DefaultDirContextValidator\"]] and x:property[@name=\"maxActive\" and @value=\"${ldap.maxActive}\"]\tand x:property[@name=\"maxTotal\" and @value=\"${ldap.maxTotal}\"] and x:property[@name=\"maxIdle\" and @value=\"${ldap.maxIdle}\"] and x:property[@name=\"minIdle\" and @value=\"${ldap.minIdle}\"] and x:property[@name=\"maxWait\" and @value=\"${ldap.maxWait}\"] and x:property[@name=\"whenExhaustedAction\" and @value=\"${ldap.whenExhaustedAction}\"] and x:property[@name=\"testOnReturn\" and @value=\"${ldap.testOnReturn}\"] and x:property[@name=\"testOnBorrow\" and @value=\"${ldap.testOnBorrow}\"] and x:property[@name=\"testWhileIdle\" and @value=\"${ldap.testWhileIdle}\"]\tand x:property[@name=\"timeBetweenEvictionRunsMillis\" and @value=\"${ldap.timeBetweenEvictionRunsMillis}\"] and x:property[@name=\"numTestsPerEvictionRun\" and @value=\"${ldap.numTestsPerEvictionRun}\"]\tand x:property[@name=\"minEvictableIdleTimeMillis\" and @value=\"${ldap.minEvictableIdleTimeMillis}\"]]";
	final String LDAP_TEMPLATE_PATTERN = "/x:beans/x:bean[@id=\"ldapTemplate\" and @class=\"org.springframework.ldap.core.LdapTemplate\" and x:constructor-arg[@ref=\"contextSource\"]]";
	final String LDAP_TEMPLATE_HOLDER_PATTERN = "/x:beans/x:bean[@id=\"ldapTemplateHolder\" and x:property[@name=\"ldapTemplate\" and @ref=\"ldapTemplate\"]]";
	
	@Override
	public void start(RuleContext ctx) {
		super.start(ctx);
	}
	@Override
	public void end(RuleContext ctx) {
		Boolean hasContextSource = (Boolean) ctx.getAttribute("CONTEXT_SOURCE");
		Boolean hasLdapTemplate = (Boolean) ctx.getAttribute("LDAP_TEMPLATE");
		Boolean hasLdapTemplateHolder = (Boolean) ctx.getAttribute("LDAP_TEMPLATE_HOLDER");
		if((hasContextSource == null) || (hasLdapTemplate == null) || 
				(hasLdapTemplateHolder == null)) {
			XmlRuleViolationFactory.INSTANCE.addViolation(ctx, this, null, "LDAP-Konfiguration ist fehlerhaft", null);
		}
		if(ctx.getAttribute("containsSicherheitXml") == null) {
			XmlRuleViolationFactory.INSTANCE.addViolation(ctx, this, null, "Sicherheit.xml fehlt!", null);
		}
		super.end(ctx);
	}
	static class SpringNamespaceContext implements NamespaceContext {
		@Override
		 public String getNamespaceURI(String prefix) {
		       if(prefix.equals("x"))
		    	   return "http://www.springframework.org/schema/beans";
		       else if(prefix.equals("aop"))
		       		return "http://www.springframework.org/schema/aop";
		       return null;		         
		}

		@Override
		public String getPrefix(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Iterator getPrefixes(String namespaceURI) {
			// TODO Auto-generated method stub
			return null;
		}
		
	}
	
	@Override
	protected void visit(XmlNode node, Document document, RuleContext ctx) {
	
			//Diff myDiff = new Diff(sicherheitXmlPattern, documentToString(document));
//			XpathEngine engine = XMLUnit.newXpathEngine();
			try {
				 XPath xPath = XPathFactory.newInstance().newXPath();
				 xPath.setNamespaceContext(new SpringNamespaceContext());
				 
				 //Überprüfe LDAP-Konfiguration
				 boolean hasContextSource = (Boolean) xPath.evaluate(CONTEXT_SOURCE_PATTERN, document, XPathConstants.BOOLEAN);
				 boolean hasLdapTemplate = (Boolean) xPath.evaluate(LDAP_TEMPLATE_PATTERN, document, XPathConstants.BOOLEAN);
				 boolean hasLdapTemplateHolder = (Boolean) xPath.evaluate(LDAP_TEMPLATE_HOLDER_PATTERN, document, XPathConstants.BOOLEAN);
				 
				 if(hasContextSource) {
					 ctx.setAttribute("CONTEXT_SOURCE", true);
//					 System.out.println("CS");
				 }
				 if(hasLdapTemplate) {
					 ctx.setAttribute("LDAP_TEMPLATE", true);
//					 System.out.println("LT");
				 }
				 if(hasLdapTemplateHolder) {
					 ctx.setAttribute("LDAP_TEMPLATE_HOLDER", true);
//					 System.out.println("LTH");
				 }
				 
				if(ctx.getSourceCodeFile() != null && ctx.getSourceCodeFile().getName().equals("sicherheit.xml")) {		 
				
				ctx.setAttribute("containsSicherheitXml", true);
				boolean hasAufrufKontext = (Boolean) xPath.evaluate(AUFRUF_KONTEXT_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasGesichertInterceptor = (Boolean) xPath.evaluate(GESICHERT_INTERCEPTOR_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasLoggingKontextInterceptor = (Boolean) xPath.evaluate(LOGGING_KONTEXT_INTERCEPTOR_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasAOPConfig = (Boolean) xPath.evaluate(AOP_CONFIG_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasAufrufKontextFactory = (Boolean) xPath.evaluate(AUFRUF_KONTEXT_FACTORY_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasAufrufKontextVerwalter = (Boolean) xPath.evaluate(AUFRUF_KONTEXT_VERWALTER_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasSicherheitAdmin = (Boolean) xPath.evaluate(SICHERHEIT_ADMIN_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasSicherheit = (Boolean) xPath.evaluate(SICHERHEIT_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasCamsAccessManager = (Boolean) xPath.evaluate(CAMS_ACCESS_MANAGER_PATTERN, document, XPathConstants.BOOLEAN);
				boolean hasCamsConfiguration = (Boolean) xPath.evaluate(CAMS_CONFIGURATION_PATTERN, document, XPathConstants.BOOLEAN);
				
//				System.out.println(hasAufrufKontext);
//				System.out.println(hasGesichertInterceptor);
//				System.out.println(hasLoggingKontextInterceptor);
//				System.out.println(hasAOPConfig);
//				System.out.println(hasAufrufKontextFactory);
//				System.out.println(hasAufrufKontextVerwalter);
//				System.out.println(hasSicherheitAdmin);
//				System.out.println(hasSicherheit);
//				System.out.println(hasCamsAccessManager);
//				System.out.println(hasCamsConfiguration);
				
				
				if(!(hasAufrufKontext && hasGesichertInterceptor && hasLoggingKontextInterceptor && hasAOPConfig && hasAufrufKontextFactory
						&& hasAufrufKontextVerwalter && hasSicherheitAdmin && hasSicherheit && hasCamsAccessManager && hasCamsConfiguration)) {
					System.out.println("Sicherheit.xml fehlerhaft");
					addViolation(ctx, node);
				} else {
					System.out.println("Sicherheit.xml vollständig");
				}
				}
			} catch (XPathExpressionException e) {
				e.printStackTrace();
			}
		
		super.visit(node, document, ctx);
	}
}

