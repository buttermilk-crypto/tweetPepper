/*
Copyright 2016, David R. Smith, All Rights Reserved

This file is part of TweetPepper.

TweetPepper is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TweetPepper is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TweetPepper.  If not, see <http://www.gnu.org/licenses/>.

*/
package com.cryptoregistry.tweet.pepper.format.img;

import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.font.LineMetrics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;

import javax.imageio.ImageIO;

import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.util.TimeUtil;

/**
 * <p>Build a suitable PNG file from scratch based on the spec instance and the KMU. This class does embed
 * the kmu, that is done with PNGSigner</p>
 * 
 * <p>Not chunk-oriented, requires a graphics context and uses ImageIO.</p>
 * 
 * @author Dave
 * @see PNGSigner
 *
 */
public class PNGWrapperGenerator {

	KMU kmu;
	PNGWrapperSpec spec;
	
	public PNGWrapperGenerator(PNGWrapperSpec spec, KMU kmu) {
		super();
		this.spec = spec;
		this.kmu = kmu;
	}
	
	public void write() {
		
		BufferedImage handImg = null;
		InputStream hand = this.getClass().getResourceAsStream("/hand-trans64a.png");
		try {
			handImg = ImageIO.read(hand);
		} catch (IOException e1) {
			throw new RuntimeException(e1);
		}
		
		// initially we need to compute some sizes based on requested font and text
		// this requires a small image so we can get a graphics context
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2 = img.createGraphics();
		String [] list = createStrings();
		
		Font f = new Font(Font.MONOSPACED,Font.PLAIN,11);
		g2.setFont(f);
		FontMetrics fm = g2.getFontMetrics(f);
		
		
		int x = 75, y=10, maxWidth = 0, maxHeight=0;
		for(String str: list){
			LineMetrics lm = fm.getLineMetrics(str, g2);
			float t_height = lm.getHeight();
			int stringWidth = fm.stringWidth(str);
			if(stringWidth>maxWidth)maxWidth = stringWidth;
			y+=t_height;
			maxHeight=y;
			//g2.drawString(str, x, y); don't actually draw here
		}
		
		// cleanup
		g2.dispose();
		
		
		// OK, we now have the measured rectangle for the text, which is x,y,maxWidth,maxHeight
		// make an image of this size and write it. 
		x = 75; y=10;
		img = new BufferedImage(maxWidth+x, maxHeight+y, BufferedImage.TYPE_INT_ARGB);
		g2 = img.createGraphics();
		g2.setRenderingHint(
		        RenderingHints.KEY_TEXT_ANTIALIASING,
		        RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		
		PlasmaFilter filter = (PlasmaFilter) Effects.plasmaFilter();
		filter.randomize();
		BufferedImage tmp = filter.filter(img, null);
		g2.drawImage(tmp, null, 0, 0);
		
		g2.drawImage(handImg, null, 10, 10);
		
		int count = 0;
		for(String str: list){
			LineMetrics lm = fm.getLineMetrics(str, g2);
			float t_height = lm.getHeight();
			y+=t_height;
			if(count==list.length-1){
				f = new Font(Font.SERIF,Font.ITALIC,10);
				g2.setFont(f);
			}
			g2.drawString(str, x, y); 
			count++;
		}
		
		// cleanup
		g2.dispose();
         
		try {
		  //  File outputfile = File.createTempFile("tp", "png");
			String outputPath = spec.get("output.path", null);
			if(outputPath == null) new RuntimeException("output.path = null, please set in spec");
			File outputfile = new File(outputPath);
			if(!outputfile.getParentFile().exists()){
				outputfile.getParentFile().mkdirs();
			}
		    ImageIO.write(img, "png", outputfile);
		} catch (IOException e) {
		   throw new RuntimeException(e);
		}
	}
	
	private String [] createStrings() {
		StringBuffer buf = new StringBuffer();
		
		if(kmu.version != null){
			buf.append(kmu.version);
			buf.append("\n\n");
		}
		
		if(kmu.kmuHandle != null){
			buf.append("Transaction Handle: ");
			buf.append(kmu.kmuHandle);
			buf.append("\n");
		}
		
		String twitterHandle = spec.get("twitter.handle", null);
		if(twitterHandle != null){
			buf.append("Twitter Handle: ");
			buf.append(twitterHandle);
			buf.append("\n");
		}
		
		if(kmu.adminEmail!=null){
			buf.append("Admin Email: ");
			buf.append(kmu.adminEmail);
			buf.append("\n");
		}
		
		buf.append("CreatedOn: ");
		buf.append(TimeUtil.now());
		buf.append("\n");
		
		
		buf.append("Contents: ");
		
		HashSet<String> set = new HashSet<String>();
		for(String key: kmu.map.keySet()) {
			set.add(String.valueOf(key.charAt(key.length()-1)));
		}
		
		Object [] array = set.toArray();
		Arrays.sort(array);
		
		StringBuffer b = new StringBuffer();
		int count = 0;
		for(Object bt: array) {
			b.append(String.valueOf(bt));
			if(count==array.length-2) b.append(", and ");
			else b.append(", ");
			count++;
		}
		b.delete(b.length()-2, b.length());
		buf.append(b.toString());
		
		buf.append(" type blocks.\n");
		
		buf.append("\n");
		buf.append("  This image file contains embedded cryptographic data.");
		
		
		return buf.toString().split("\\n");
	}

}
