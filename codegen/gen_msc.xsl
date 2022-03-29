<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" xmlns:math="http://exslt.org/math" xmlns:func="http://exslt.org/functions" xmlns:str="http://exslt.org/strings" xmlns:dyn="http://exslt.org/dynamic" xmlns:set="http://exslt.org/sets" xmlns:sets="http://exslt.org/sets" xmlns:date="http://exslt.org/dates-and-times" xmlns:yml="http://fdik.org/yml" extension-element-prefixes="exsl func str dyn set sets math date yml">
<xsl:output method="text"/>
<xsl:variable name="space" select="'                                                                                                                                                                                                        '"/>
<xsl:param name="autoindent" select="4"/>
<xsl:template match="text()"/>
<xsl:variable name="maxdepth" select="20"/>
<xsl:template match="/protocol/fsm[1]">
<xsl:param name="_indent" select="0"/>
<xsl:variable name="msc">
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  # The entities
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  ua [label="Alice\nUser"], a [label="Alice\nDevice"], b [label="Bob\nDevice"], ub [label="Bob\nUser"];
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>

</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  # Small gap before the boxes
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  |||;
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>

</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  # Next two on same line due to ','
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  a box a [label="Sole"],
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
  b box b [label="Sole"];
</xsl:text>
</xsl:variable>
<xsl:apply-templates select="//event[@name='Accept']">
<xsl:with-param name="_indent" select="$_indent + (1) * $autoindent"/>
<xsl:with-param name="commPartnerState" select="'Sole'"/>
<xsl:with-param name="whoAmI" select="'a'"/>
<xsl:with-param name="commPartner" select="'b'"/>
<xsl:with-param name="msc" select="$msc"/>
</xsl:apply-templates>
</xsl:template>
<xsl:template match="protocol/fsm[1]/*/event">
<xsl:param name="_indent" select="0"/>
<xsl:param name="commPartnerState"/>
<xsl:param name="whoAmI"/>
<xsl:param name="commPartner"/>
<xsl:param name="msc"/>
<xsl:variable name="ownState" select="parent::state/@name"/>
<xsl:variable name="stopTheRecursion" select="parent::state/@timeout='on' or $_indent&gt;$maxdepth"/>
<xsl:variable name="event" select="@name"/>
<xsl:variable name="eventString">
<xsl:if test="/protocol/fsm[1]">
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
u</xsl:text>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 -&gt; </xsl:text>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 [label="</xsl:text>
<xsl:value-of select="$event"/>
<xsl:text>
]";
</xsl:text>
</xsl:if>
</xsl:variable>
<xsl:value-of select="$eventString">
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>

</xsl:text>
</xsl:value-of>
<xsl:value-of select="$event"/>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>

</xsl:text>
<xsl:for-each select="descendant::send[last()]|descendant::transition[last()]">
<xsl:variable name="message" select="@name"/>
<xsl:variable name="condition" select="ancestor::condition/@name"/>
<xsl:variable name="target">
<xsl:choose>
<xsl:when test="following-sibling/transition/@name">
<xsl:value-of select="following-sibling/transition/@name"/>
</xsl:when>
<xsl:otherwise>
<xsl:value-of select="ancestor::state/@name"/>
</xsl:otherwise>
</xsl:choose>
</xsl:variable>
<xsl:choose>
<xsl:when test="stopTheRecursion">
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
msc {
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
   </xsl:text>
<xsl:value-of select="$msc"/>
<xsl:text>

</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
}
</xsl:text>
</xsl:when>
<xsl:when test="$message and $target=$ownState and $_indent&lt;$maxdepth">
<xsl:variable name="newmsc">
<xsl:value-of select="$msc"/>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 -&gt; </xsl:text>
<xsl:value-of select="$commPartner"/>
<xsl:text>
 [label="</xsl:text>
<xsl:value-of select="$message"/>
<xsl:text>
"];
</xsl:text>
</xsl:variable>
<xsl:apply-templates select="/protocol/fsm[1]/state[@name=$commPartnerState]/event[@name=$message]">
<xsl:with-param name="_indent" select="$_indent + (1) * $autoindent"/>
<xsl:with-param name="commPartnerState" select="$ownState"/>
<xsl:with-param name="whoAmI" select="$commPartner"/>
<xsl:with-param name="commPartner" select="$whoAmI"/>
<xsl:with-param name="msc" select="$newmsc"/>
</xsl:apply-templates>
</xsl:when>
<xsl:when test="$message and not($target=$ownState)">
<xsl:variable name="newmsc">
<xsl:value-of select="$msc"/>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 -&gt; </xsl:text>
<xsl:value-of select="$commPartner"/>
<xsl:text>
 [label="</xsl:text>
<xsl:value-of select="$message"/>
<xsl:text>
"];
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 box </xsl:text>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
     [label="</xsl:text>
<xsl:value-of select="$target"/>
<xsl:text>
"];
</xsl:text>
</xsl:variable>
<xsl:apply-templates select="/protocol/fsm[1]/state[@name=$commPartnerState]/event[@name=$message]">
<xsl:with-param name="_indent" select="$_indent + (1) * $autoindent"/>
<xsl:with-param name="commPartnerState" select="$target"/>
<xsl:with-param name="whoAmI" select="$commPartner"/>
<xsl:with-param name="commPartner" select="$whoAmI"/>
<xsl:with-param name="msc" select="$newmsc"/>
</xsl:apply-templates>
</xsl:when>
<xsl:when test="not($message or $target=$ownState)">
<xsl:variable name="newmsc">
<xsl:value-of select="$msc"/>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
 box </xsl:text>
<xsl:value-of select="$whoAmI"/>
<xsl:text>
     [label="</xsl:text>
<xsl:value-of select="$target"/>
<xsl:text>
"];
</xsl:text>
</xsl:variable>
<xsl:apply-templates select="/protocol/fsm[1]/state[@name=$target]/event[@name='Init']">
<xsl:with-param name="_indent" select="$_indent + (1) * $autoindent"/>
<xsl:with-param name="commPartnerState" select="$commPartnerState"/>
<xsl:with-param name="whoAmI" select="$whoAmI"/>
<xsl:with-param name="commPartner" select="$commPartner"/>
<xsl:with-param name="msc" select="$newmsc"/>
</xsl:apply-templates>
</xsl:when>
<xsl:otherwise>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
msc {
</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
   </xsl:text>
<xsl:value-of select="$msc"/>
<xsl:text>

</xsl:text>
<xsl:value-of select="substring($space, 1, $_indent+0*$autoindent)"/>
<xsl:text>
}
</xsl:text>
</xsl:otherwise>
</xsl:choose>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>

