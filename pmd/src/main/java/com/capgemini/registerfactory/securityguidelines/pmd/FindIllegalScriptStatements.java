package com.capgemini.registerfactory.securityguidelines.pmd;
import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractDomXmlRule;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
   
public class FindIllegalScriptStatements extends AbstractDomXmlRule {
	
	final String EVENT_HANDLER_PATTERN = "//*[@onabort or @onblur or @onclick or @ondblclick or @onerror or @onfocus or @onkeydown or @onkeypress or @onkeyup or @onload or @onmousedown or @onmousemove or @onmouseout or @onmouseover or @onmouseup or @onreset or @onselect or @onsubmit or @onunload]";
	final String SCRIPT_IN_LINK_PATTERN = "//a[starts-with(@href, \"javascript:\") or starts-with(@href, \"vbscript:\")]"; 
	
	@Override
	protected void visit(XmlNode node, Document document, RuleContext ctx) {
		 XPath xPath = XPathFactory.newInstance().newXPath();
		
		try {
			boolean hasEventHandlers = (Boolean) xPath.evaluate(EVENT_HANDLER_PATTERN, document, XPathConstants.BOOLEAN);
			boolean hasScriptInLinks = (Boolean) xPath.evaluate(SCRIPT_IN_LINK_PATTERN, document, XPathConstants.BOOLEAN);

			if(hasEventHandlers || hasScriptInLinks) {
				addViolation(ctx, node);
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		super.visit(node, document, ctx);
	}
	
	@Override
	protected void visit(XmlNode node, Element element, RuleContext ctx) {
		
		
		if(element.getTagName().equals("script")) {
			addViolation(ctx, node);
		}
		super.visit(node, element, ctx);
	}

}
