<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
  <body>
	  <!--<h2>Complete List of Sync</h2>
  <table border="1">
	  <tr>
		  <th>Protocol</th>
		  <th>FSM</th>
		  <th>state</th>
		  <th>message</th>
		  <th>event</th>
		  <th>transition</th>
		  <th>name of member</th>
		  <th>type</th>
	  </tr>
  <xsl:for-each select="descendant::transition | descendant::message"> 
	<xsl:variable name="event" select="ancestor::event/@name"/>
	<xsl:variable name="name" select="@name"/>
			  <xsl:variable name="bgc">
	  <xsl:choose>
		  <xsl:when test="ancestor::fsm/message[@name=$event]">
			  "orange"
		  </xsl:when>
		  <xsl:otherwise>
			  orange
		  </xsl:otherwise>
	  </xsl:choose>
			  </xsl:variable>

	  <tr bgcolor='{$bgc}'>
	  <td><xsl:value-of select="ancestor-or-self::protocol/@name"/></td>
	  <td><xsl:value-of select="ancestor-or-self::fsm/@name"/></td>
	  <td><xsl:value-of select="ancestor-or-self::state/@name"/></td>
	  <td><xsl:value-of select="ancestor-or-self::*/message[@name=$event]/@name"/></td>
	  <td><xsl:value-of select="ancestor-or-self::event/@name"/></td>
	  <td><xsl:value-of select="ancestor-or-self::transition/@name"/></td>
	  <td><xsl:value-of select="@name"/></td><td>(<xsl:value-of select="name()"/>)</td>
	  </tr>
    </xsl:for-each>
    </table>-->
    <h2>List of transitions starting from persistent state</h2>
  <table border="1">
	  <tr>
		  <th>state</th>
		  <th>event</th>
		  <th>transition</th>
		  <th>sent message</th>
	  </tr>
	  <xsl:apply-templates select="state[@timeout='off']"/>
  </table>
  </body>
  </html>
</xsl:template>

<xsl:template match="state[@timeout='off']">
	  <td><xsl:value-of select="@name"/></td>
	  <td><xsl:value-of select="child::event/@name"/></td>
	  <td><xsl:value-of select="descendant::transition/@name"/></td>
	  <!--	  <td><xsl:value-of select="descendant::send/@name"/></td>-->
</xsl:template>

</xsl:stylesheet> 
