/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.util;


import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**<pre>
 * Used for ISO 8601 formatting, which is our standard for date-time values. Reworked as per 
 * http://stackoverflow.com/questions/2201925/converting-iso-8601-compliant-string-to-java-util-date
 * 
 * This breaks my old examples but needs to be fixed
 *
 * </pre>
 * @author Dave
 *
 */
public class TimeUtil {
	
	private static Lock lock = new ReentrantLock();

	public static String format(Date date) {
		 lock.lock(); 
		  try {
			  Calendar c = GregorianCalendar.getInstance();
			  c.setTime(date);
			  return javax.xml.bind.DatatypeConverter.printDateTime(c);
		 } finally {
		     lock.unlock();
		 }
	}
	
	
	public static final Date getISO8601FormatDate(String in) {
		 lock.lock(); 
	     try {
	    	 try {
	    	 Calendar cal = javax.xml.bind.DatatypeConverter.parseDateTime(in);
	    	 return cal.getTime();
	    	 }catch(IllegalArgumentException x){
	    		 // handle incorrectly formatted dates
	    		 TimeZone tz = TimeZone.getTimeZone("UTC");
		 		 DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		 		 df.setTimeZone(tz);
		 		 try {
					return df.parse(in);
				} catch (ParseException e) {
					return new Date();
				}
	    	 }
	     } finally {
	       lock.unlock();
	     }
	}
	
	public static final String now() {
		 lock.lock(); 
	     try {
	    	return format(new Date());
	     } finally {
	       lock.unlock();
	     }
	}

}
