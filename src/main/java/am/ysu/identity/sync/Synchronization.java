package am.ysu.identity.sync;

import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wrapper class around a mutex
 */
public class Synchronization
{
    /**
     * All sync objects generated will be held here
     */
    private static final Map<Serializable, Synchronization> mutexes = new ConcurrentHashMap<>();

    private final Object mutex;

    private Synchronization()
    {
        mutex = new Object(){};
    }

    /**
     * Execute a returning call using the mutex for synchronization
     * @param callable The call to execute
     * @param <T> Return value type
     * @return The result of the call
     * @throws Exception if the callable throws an exception
     */
    public <T> T execute(Callable<T> callable) throws Exception
    {
        synchronized (mutex){
            return callable.call();
        }
    }

    /**
     * Execute a task without return value using the mutex for synchronization
     * @param runnable The task to execute
     */
    public void execute(Runnable runnable)
    {
        synchronized (mutex){
            runnable.run();
        }
    }

    /**
     * Creates a mutex with a specific id, or returns an already existing one
     * @param id The id for the mutex
     * @return The Synchronization object for that mutex
     */
    public static Synchronization lockingOn(Serializable id)
    {
        Synchronization sync = mutexes.get(id);
        if(sync == null){
            sync =  new Synchronization();
            mutexes.put(id, sync);
        }
        return sync;
    }
}
