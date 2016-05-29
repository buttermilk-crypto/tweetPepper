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
 * </pre>
 * 
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
