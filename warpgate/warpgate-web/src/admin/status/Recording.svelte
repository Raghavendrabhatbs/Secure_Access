<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { api, type Recording, RecordingKind } from 'admin/lib/api'
    import DesktopRecordingPlayer from 'admin/player/DesktopRecordingPlayer.svelte'
    import TerminalRecordingPlayer from 'admin/player/TerminalRecordingPlayer.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'
    import KubernetesRecording from './KubernetesRecording.svelte'

    interface Props {
        params: { id: string }
        watchMode?: boolean
    }

    let { params = { id: '' }, watchMode = false }: Props = $props()

    let error: string | null = $state(null)

    import { adminPermissions } from '../lib/store'

    let recording: Recording | null = $state(null)

    async function load() {
        if (!$adminPermissions.recordingsView) {
            error = 'You do not have permission to view recordings.'
            return
        }
        recording = await api.getRecording(params)
        if (
            watchMode &&
            (recording.ended || recording.kind !== RecordingKind.Terminal)
        ) {
            error = 'Live session Watch is available only for active terminal sessions.'
            recording = null
        }
    }

    function getTCPDumpURL() {
        return `/@warpgate/admin/api/recordings/${recording?.id}/tcpdump`
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })
</script>

<div class="page-summary-bar">
    <h1>{watchMode ? 'live session watch' : 'session recording'}</h1>
    <a class="recordings-back-button" href={watchMode ? '/status/sessions' : '/admin/recordings'}>
        {watchMode ? 'Back to Sessions' : 'Back to Recordings'}
    </a>
</div>

{#if !recording && !error}
    <DelayedSpinner />
{/if}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if recording?.kind === RecordingKind.Traffic}
    <a href={getTCPDumpURL()}>Download tcpdump file</a>
{/if}
{#if recording?.kind === RecordingKind.Terminal}
    <TerminalRecordingPlayer {recording} {watchMode} />
{/if}
{#if recording?.kind === RecordingKind.Desktop}
    <DesktopRecordingPlayer {recording} />
{/if}
{#if recording?.kind === RecordingKind.Kubernetes}
    <KubernetesRecording {recording} />
{/if}

<style>
    .page-summary-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
    }

    .recordings-back-button {
        height: 28px;
        padding: 0 9px;
        display: inline-flex;
        align-items: center;
        border: 1px solid #d8dee5;
        border-radius: 5px;
        background: #ffffff;
        color: #364152;
        font-size: 10px;
        text-decoration: none;
        white-space: nowrap;
    }

    .recordings-back-button:hover {
        background: #f7f8fa;
        color: #182230;
    }

    .recordings-back-button:focus-visible {
        outline: 2px solid #4678c8;
        outline-offset: 2px;
    }
</style>
