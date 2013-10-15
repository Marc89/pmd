package com.capgemini.registerfactory.securityguidelines.pmd;

import java.util.Iterator;
import java.util.List;

import org.jaxen.JaxenException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.ast.xpath.Attribute;
import net.sourceforge.pmd.lang.dfa.DataFlowNode;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractDomXmlRule;
import net.sourceforge.pmd.lang.xml.rule.XmlRuleViolationFactory;

public class MissingNamedQueries extends AbstractDomXmlRule {
	@Override
	public void start(RuleContext ctx) {
		// TODO Auto-generated method stub
		ctx.setAttribute("hasNamedQuery", false);
		super.start(ctx);
	}
	@Override
	public void end(RuleContext ctx) {
		// TODO Auto-generated method stub
		
		if  (!((Boolean)ctx.getAttribute("hasNamedQuery")).booleanValue()) {
			 System.out.println(ctx.getSourceCodeFilename() +  "Kein Named Query");
			 
			 //addViolation doesn't work without refering to an explicit source file
			 XmlRuleViolationFactory.INSTANCE.addViolation(ctx, this, null, this.getMessage(), null);
			
		}	
		super.end(ctx);
	}
	
	@Override
	protected void visit(XmlNode node, Document document, RuleContext ctx) {
		if(ctx.getSourceCodeFile().getName().equals("NamedQueries.hbm.xml")) {
			ctx.removeAttribute("hasNamedQuery"); // bestehende Werte können nicht überschrieben werden
			ctx.setAttribute("hasNamedQuery", true);
		}
		
		
		//System.out.println(ctx.getSourceCodeFile().getName());
		super.visit(node, document, ctx);
	}
}
