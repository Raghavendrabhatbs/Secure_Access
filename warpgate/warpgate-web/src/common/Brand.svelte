<script lang="ts">
    import { currentThemeFile } from 'theme'
</script>

<div class="brand" class:light={$currentThemeFile === 'light'}>
    <svg
        class="brand-mark"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
    >
        <path
            d="M12 2.5 20 6v5.7c0 4.8-3.2 8.5-8 9.8-4.8-1.3-8-5-8-9.8V6l8-3.5Z"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linejoin="round"
        />
        <path
            d="m8.5 12 2.2 2.2 4.8-4.8"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linecap="round"
            stroke-linejoin="round"
        />
    </svg>
    <span>SecureAccess</span>
</div>

<style lang="scss">
    .brand {
        display: flex;
        align-items: center;
        gap: 6px;
        height: 22px;
        color: #cbd4eb;
        font-size: 16px;
        font-weight: 650;
        letter-spacing: -0.035em;
        white-space: nowrap;
    }

    .brand.light {
        color: #313948;
    }

    .brand-mark {
        width: 22px;
        height: 22px;
        flex: none;
    }
</style>
