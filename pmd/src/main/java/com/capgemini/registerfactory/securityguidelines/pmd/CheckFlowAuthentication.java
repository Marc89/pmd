package com.capgemini.registerfactory.securityguidelines.pmd;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractDomXmlRule;
import net.sourceforge.pmd.lang.xml.rule.XmlRuleViolationFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class CheckFlowAuthentication extends AbstractDomXmlRule {
	
	final String SECURITY_CONSTRAINTS_PATTERN ="/web-app/security-constraint";
	final String ROLE_NAME_PATTERN = "auth-constraint/role-name/text()";
	final String URL_PATTERN = "web-resource-collection/url-pattern/text()";
	
	
	//final String sicherheitXmlPattern = "<beans xmlns=\"http://www.springframework.org/schema/beans\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:aop=\"http://www.springframework.org/schema/aop\" xmlns:sec=\"http://www.springframework.org/schema/security\" xsi:schemaLocation=\"http://www.springframework.org/schema/beans  http://www.springframework.org/schema/beans/spring-beans-2.5.xsd  http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security-2.0.4.xsd http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop-2.0.xsd\"><bean id=\"aufrufKontextInterceptor\" class=\"de.bund.bva.pliscommon.aufrufkontext.service.StelltAufrufKontextBereitIn terceptor\"><property name=\"aufrufKontextVerwalter\" ref=\"aufrufKontextVerwalter\" /><property name=\"aufrufKontextFactory\" ref=\"aufrufKontextFactory\" /></bean><bean id=\"gesichertInterceptor\" class=\"de.bund.bva.pliscommon.sicherheit.annotation.GesichertInterceptor\"><property name=\"sicherheit\" ref=\"sicherheit\" /><property name=\"sicherheitAttributeSource\"><bean class=\"de.bund.bva.pliscommon.sicherheit.annotation. AnnotationSicherheitAttributeSource\" /></property></bean><bean id=\"loggingKontextIntercepter\" class=\"de.bund.bva.pliscommon. aufrufkontext.service.StelltLoggingKontextBereitInterceptor\" /><aop:config><aop:pointcut id=\"loggingKontextPointcut\" expression=\"@annotation(de.bund.bva.pliscommon.aufrufkontext.service.StelltLogg ingKontextBereit) || @within(de.bund.bva.pliscommon.aufrufkontext.  service.StelltLoggingKontextBereit)\" /><aop:pointcut id=\"aufrufKontextPointcut\" expression=\"@annotation(de.bund.bva.pliscommon.aufrufkontext.service.StelltAufr ufKontextBereit) ||  @within(de.bund.bva.pliscommon.aufrufkontext.service.StelltAufrufKontextBereit) \" /><aop:pointcut id=\"gesichertPointcut\" expression=\"@annotation(de.bund.bva.pliscommon.sicherheit.annotation.Gesichert)  || @within(de.bund.bva.pliscommon.sicherheit.annotation.Gesichert)\" /><aop:advisor pointcut-ref=\"loggingKontextPointcut\" advice-ref=\"loggingKontextIntercepter\" order=\"50\" /><aop:advisor pointcut-ref=\"aufrufKontextPointcut\" advice-ref=\"aufrufKontextInterceptor\" order=\"50\" /><aop:advisor pointcut-ref=\"gesichertPointcut\" advice-ref=\"gesichertInterceptor\" order=\"100\" /></aop:config><!-- Factory zum Erzeugen neuer Aufruf-Kontexte --><bean id=\"aufrufKontextFactory\" class=\"de.bund.bva.pliscommon.aufrufkontext.impl.AufrufKontextFactoryImpl\"><property name=\"aufrufKontextKlasse\" value=\"de.bund.bva.pliscommon.kontext.BehoerdenverzeichnisAufrufKontext\" /></bean><!-- AufrufKontextVerwalter definieren (jeder Request hat einen eigenen --><bean id=\"aufrufKontextVerwalter\" scope=\"request\" class=\"de.bund.bva.pliscommon.aufrufkontext.impl.AufrufKontextVerwalterImpl\"><aop:scoped-proxy /></bean><!-- Zur \u00DCberwachung der Verf\u00FCgbarkeit des Cams --><bean id=\"sicherheitAdmin\" class=\"de.bund.bva.pliscommon.sicherheit.impl.SicherheitAdminImpl\"><property name=\"accessManager\" ref=\"camsAccessManager\" /></bean><!-- \u00DCber diese Bean wird die Komponente Sicherheit Einsatzbereit gemacht --><bean id=\"sicherheit\" class=\"de.bund.bva.pliscommon.sicherheit.impl.SicherheitImpl\"><property name=\"rollenRechteDateiPfad\" value=\"/resources/sicherheit/rollenrechte.xml\" /><property name=\"aufrufKontextVerwalter\" ref=\"aufrufKontextVerwalter\" /><property name=\"accessManager\" ref=\"camsAccessManager\" /><property name=\"konfiguration\" ref=\"konfiguration\" /><property name=\"aufrufKontextFactory\" ref=\"aufrufKontextFactory\" /></bean><!-- ====================================================================== Definition der Komponente 'AccessManager'  ======================================================================  --><bean id=\"camsAccessManager\" class=\"de.bund.bva.pliscommon.sicherheit.impl.CamsAccessManagerImpl\" depends-on=\"konfiguration\"><constructor-arg index=\"0\"><ref bean=\"camsConfiguration\" /></constructor-arg><constructor-arg index=\"1\"><ref bean=\"konfiguration\" /></constructor-arg></bean><bean id=\"camsConfiguration\" class=\"org.springframework.core.io.ClassPathResource\"><constructor-arg value=\"/config/cams-webagent.conf\" /></bean></beans>";
	
	List<String> definedFlows = new ArrayList<String>();
	@Override
	public void start(RuleContext ctx) {
		//System.out.println("StartCheckSpring");
		definedFlows = Collections.synchronizedList(new ArrayList<String>());
		//ctx.setAttribute("definedFlows", definedFlows);
		super.start(ctx);
	}
	@Override
	public void end(RuleContext ctx) {
	
		//TODO: plisCommonFlow 
	
	
		List<String> flows = (List<String>) ctx.getAttribute("definedFlows");
		NodeList constraints = (NodeList) ctx.getAttribute("nodeList");
		if(constraints != null) {
		//System.out.println(constraints.toString());
		 XPath xPath = XPathFactory.newInstance().newXPath();
		 xPath.setNamespaceContext(new SpringNamespaceContext());
		for(int i = 0; i < constraints.getLength(); i++) {
			Node n = constraints.item(i);
			try {
				
				
				if(!xPath.evaluate(ROLE_NAME_PATTERN, n).isEmpty()) { //Eine Rolle ist definiert
					NodeList urls = (NodeList) xPath.evaluate(URL_PATTERN, n, XPathConstants.NODESET);
					for(int j = 0; j < urls.getLength(); j++) {
						String url = urls.item(j).getNodeValue();
						//System.out.println(url.substring(url.lastIndexOf("/")+1));
						
						//entferne die Flows, für die Rollen definiert sind
						flows.remove(url.substring(url.lastIndexOf("/")+1));
					}
				}
			} catch (XPathExpressionException e) {
			}
			
		}
		}
		if(flows != null && flows.size() != 0) {
		
			
			XmlRuleViolationFactory.INSTANCE.addViolation(ctx, this, null, "Folgende Flows sind ohne Authorisierung zugänglich: " + flows.toString(), null);
		System.out.println("GEFAHR:"); 
		for(String s : flows) {
			
			
			System.out.println(s);
		}
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
			
		 XPath xPath = XPathFactory.newInstance().newXPath();
		 xPath.setNamespaceContext(new SpringNamespaceContext());
		 
		if(ctx.getSourceCodeFile() != null &&
				ctx.getSourceCodeFile().getName().endsWith("Flow.xml") && 
				!ctx.getSourceCodeFile().getName().equals("plisParentFlow.xml") ) { 		 
			String name = ctx.getSourceCodeFile().getName();
			definedFlows.add(name.substring(0, name.lastIndexOf(".xml")));
			ctx.setAttribute("definedFlows", definedFlows);
			//System.out.println(definedFlows.size());
			//System.out.println(name);
		} else
			try {
				if(ctx.getSourceCodeFile() != null && ctx.getSourceCodeFile().getCanonicalPath().endsWith("WEB-INF"+File.separator+"web.xml")) {
					//System.out.println("web.xml");
					NodeList nodeList = (NodeList) xPath.evaluate(SECURITY_CONSTRAINTS_PATTERN, document, XPathConstants.NODESET);
					ctx.setAttribute("nodeList", nodeList);
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (XPathExpressionException e) {
				e.printStackTrace();
			}
		super.visit(node, document, ctx);
	}
}

