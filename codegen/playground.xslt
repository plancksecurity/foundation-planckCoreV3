<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"> 
	<xsl:template match="/">
digraph SEQ_DIAGRAM {
    graph [overlap=true, splines=line, nodesep=1.0, ordering=out];
    edge [arrowhead=none];
    node [shape=none, width=0, height=0, label=""];

    {
        rank=same;
        node[shape=rectangle, height=0.7, width=2];
        ext_a[style=invis];
        api_a[label="Alice"];
        api_b[label="Bob"];
        ext_b[style=invis];
    }
    // Draw vertical lines
    {
        edge [style=dashed, weight=6];
        api_a -> a1 ;
        a2 -> a3;
        a3 -> a4 [penwidth=10, style=solid];
        a4 -> a5;
    }
    {
        edge [style=dashed, weight=6];
        api_b -> b1;
        b2 -> b3 -> b4;
        b4 -> b5 [penwidth=5; style=solid];
    }
    {
        edge [style=invis, weight=6];
        ext_a -> c1 -> c2 -> c3 -> c4 -> c5;
    }
    {
        edge [style=invis, weight=6];
        ext_b -> d1 -> d2 -> d3 -> d4 -> d5;
    }
    // Draws activations
		<xsl:for-each select="message">
			{ rank=same;
			<xsl:choose>
				<xsl:when test=""/>
			</xsl:choose>
		</xsl:for-each>
    { rank=same; a1 -> b1 [label="activate()"]; c1 -> a1 [arrowhead=normal]; }
    { edge [style=dashed, weight=6]; a1->a2; b1->b2; } 
    { rank=same; a2 -> b2 [style=invis]; c2 -> a2 [label="refund()", arrowhead=normal, dir=back]; }
    { rank=same; a3 -> b3 [arrowhead=normal, dir=back, label="place_order()"]; c3 -> a3; }
    { rank=same; a4 -> b4 [label="distribute()", arrowhead=normal]; }
    { rank=same; a5 -> b5 [style=invis]; c5 -> a5 [label="bill_order()", arrowhead=normal]; }
}

	</xsl:template>
</xsl:stylesheet>

