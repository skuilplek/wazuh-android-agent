package io.github.hannescoetzee.wazuhagent.queue

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "events")
data class QueuedEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val location: String,
    val message: String,
    val createdAt: Long,
)

@Dao
interface EventDao {
    @Insert
    suspend fun insert(event: QueuedEvent): Long

    @Insert
    fun insertBlocking(event: QueuedEvent): Long

    @Query("SELECT * FROM events ORDER BY id ASC LIMIT :limit")
    suspend fun oldest(limit: Int): List<QueuedEvent>

    @Query("DELETE FROM events WHERE id IN (:ids)")
    suspend fun delete(ids: List<Long>)

    @Query("SELECT COUNT(*) FROM events")
    fun observeCount(): Flow<Int>

    @Query("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT :keep)")
    suspend fun trimTo(keep: Int)

    @Query("DELETE FROM events")
    suspend fun clear()
}

@Database(entities = [QueuedEvent::class], version = 1, exportSchema = true)
abstract class EventDatabase : RoomDatabase() {
    abstract fun events(): EventDao

    companion object {
        fun create(context: Context): EventDatabase =
            Room.databaseBuilder(context, EventDatabase::class.java, "event-queue.db").build()
    }
}
