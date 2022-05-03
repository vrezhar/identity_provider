package am.ysu.identity.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

public class DateTools
{
    private DateTools(){}

    public static Date toDate(long epochSeconds)
    {
        final Instant instant = Instant.ofEpochSecond(epochSeconds);
        return Date.from(instant);
    }

    public static Date toDate(String epochSecondString){
        return toDate(Long.parseLong(epochSecondString));
    }

    public static Date toDate(ZonedDateTime zonedDateTime){
        return Date.from(zonedDateTime.toInstant());
    }

    public static ZonedDateTime toZonedTime(Date date) {
        return ZonedDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
    }
}
